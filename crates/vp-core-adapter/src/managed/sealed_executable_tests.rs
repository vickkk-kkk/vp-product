use super::*;
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Barrier,
    },
    time::Duration,
};
const SWAP_TEST:&str="managed::sealed_executable::linux::tests::sealed_image_executes_reviewed_bytes_after_path_swap_and_inode_rewrite";
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "vp-sealed-exec-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
    fn file(&self) -> PathBuf {
        self.0.join("worker")
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn digest(path: &Path) -> String {
    let mut file = File::open(path).unwrap();
    let mut hash = Sha256::new();
    let mut bytes = [0; 65536];
    loop {
        let n = file.read(&mut bytes).unwrap();
        if n == 0 {
            break;
        }
        hash.update(&bytes[..n]);
    }
    format!("{:x}", hash.finalize())
}
fn worker(path: &Path) -> VerifiedWorker {
    VerifiedWorker {
        path: path.to_path_buf(),
        sha256: digest(path),
    }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn fixture_child() -> bool {
    if std::env::args().next().as_deref() != Some("vp-sealed-worker") {
        return false;
    }
    // No inherited copy of the executable fd survived CLOEXEC. /proc/self/exe is
    // kernel-held and can then be opened to prove the exact image bytes/seals.
    for entry in std::fs::read_dir("/proc/self/fd").unwrap().flatten() {
        if let Ok(target) = std::fs::read_link(entry.path()) {
            assert!(
                !target
                    .to_string_lossy()
                    .contains("memfd:vp-reviewed-worker"),
                "executable fd leaked across exec"
            );
        }
    }
    let exe = File::open("/proc/self/exe").unwrap();
    assert!(fcntl_get_seals(&exe).unwrap().contains(required_seals()));
    drop(exe);
    println!(
        "SEALED_IMAGE_SHA256={}",
        digest(Path::new("/proc/self/exe"))
    );
    true
}
fn child_output(mut child: Child) -> String {
    struct Guard(Child);
    impl Drop for Guard {
        fn drop(&mut self) {
            if !matches!(self.0.try_wait(), Ok(Some(_))) {
                let _ = self.0.kill();
            }
            let _ = self.0.wait();
        }
    }
    child.stdin.take();
    let output = child.stdout.take().unwrap();
    let mut child = Guard(child);
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        output.take(65536).read_to_end(&mut bytes).unwrap();
        bytes
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.0.kill().unwrap();
            let _ = child.0.wait();
            let _ = reader.join();
            panic!("sealed child timed out");
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let output = String::from_utf8(reader.join().unwrap()).unwrap();
    assert!(status.success(), "sealed child failed: {output}");
    output
}
#[test]
fn sealed_image_executes_reviewed_bytes_after_path_swap_and_inode_rewrite() {
    if fixture_child() {
        return;
    }
    for replace_inode in [true, false] {
        let scratch = Scratch::new();
        let path = scratch.file();
        std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let verified = worker(&path);
        let captured =
            SealedExecutable::capture(&verified, deadline(), &Cancellation::default()).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let trigger = barrier.clone();
        let mutate_path = path.clone();
        let thread = std::thread::spawn(move || {
            trigger.wait();
            if replace_inode {
                std::fs::rename(&mutate_path, mutate_path.with_extension("original")).unwrap();
            }
            std::fs::write(
                &mutate_path,
                b"not the reviewed executable; path exec must never reach this",
            )
            .unwrap();
        });
        // Deterministic attacker interleaving: hash/seal has finished; mutate the
        // source pathname OR the same source inode before the actual exec syscall.
        barrier.wait();
        thread.join().unwrap();
        assert_ne!(digest(&path), verified.sha256);
        assert!(fcntl_get_seals(&captured.file)
            .unwrap()
            .contains(required_seals()));
        assert!(rustix::io::fcntl_getfd(&captured.file)
            .unwrap()
            .contains(rustix::io::FdFlags::CLOEXEC));
        let mut writable = &captured.file;
        assert!(writable.write_all(b"mutation").is_err());
        assert!(captured.file.set_len(0).is_err());
        assert!(rustix::fs::fchmod(&captured.file, Mode::from_raw_mode(0o700)).is_err());
        let child = captured
            .spawn(
                &["--exact", SWAP_TEST, "--nocapture", "--test-threads=1"],
                deadline(),
                &Cancellation::default(),
            )
            .unwrap();
        drop(captured);
        let output = child_output(child);
        assert!(
            output.contains(&format!("SEALED_IMAGE_SHA256={}", verified.sha256)),
            "child did not execute the reviewed snapshot: {output}"
        );
    }
}
#[test]
fn sealed_source_rejects_script_empty_wrong_arch_symlink_and_oversize() {
    let scratch = Scratch::new();
    let path = scratch.file();
    let mut native = [0_u8; 64];
    File::open(std::env::current_exe().unwrap())
        .unwrap()
        .read_exact(&mut native)
        .unwrap();
    for bytes in [
        Vec::new(),
        b"#!/bin/sh\n# A synthetic script must never execute.\n".repeat(2),
        {
            let mut header = native[..64].to_vec();
            header[18] = 0xff;
            header[19] = 0xff;
            header
        },
    ] {
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            SealedExecutable::capture(&worker(&path), deadline(), &Cancellation::default()),
            Err(Failure::WorkerIdentityMismatch)
        ));
    }
    let file = File::options()
        .write(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    file.set_len(MAX_WORKER_EXECUTABLE_BYTES + 1).unwrap();
    drop(file);
    let oversized = VerifiedWorker {
        path: path.clone(),
        sha256: "0".repeat(64),
    };
    assert!(matches!(
        SealedExecutable::capture(&oversized, deadline(), &Cancellation::default()),
        Err(Failure::WorkerIdentityMismatch)
    ));
    std::fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(std::env::current_exe().unwrap(), &path).unwrap();
    assert!(matches!(
        SealedExecutable::capture(&oversized, deadline(), &Cancellation::default()),
        Err(Failure::WorkerIdentityMismatch)
    ));
}
#[test]
fn sealed_source_bad_digest_canceled_and_expired_never_spawn() {
    let path = std::env::current_exe().unwrap();
    let mut verified = worker(&path);
    verified.sha256 = "0".repeat(64);
    assert!(matches!(
        SealedExecutable::capture(&verified, deadline(), &Cancellation::default()),
        Err(Failure::WorkerIdentityMismatch)
    ));
    let cancel = Cancellation::default();
    cancel.cancel();
    assert!(matches!(
        SealedExecutable::capture(&verified, deadline(), &cancel),
        Err(Failure::Canceled)
    ));
    assert!(matches!(
        SealedExecutable::capture(&verified, Instant::now(), &Cancellation::default()),
        Err(Failure::Timeout)
    ));
}

#[test]
fn bounded_constructor_rejects_fifo_without_legacy_blocking_open() {
    let scratch = Scratch::new();
    let path = scratch.file();
    let directory = File::open(&scratch.0).unwrap();
    rustix::fs::mkfifoat(&directory, "worker", Mode::from_raw_mode(0o600)).unwrap();
    let start = Instant::now();
    assert!(matches!(
        VerifiedWorker::with_deadline(
            &path,
            &"0".repeat(64),
            start + Duration::from_secs(2),
            &Cancellation::default()
        ),
        Err(Failure::WorkerIdentityMismatch)
    ));
    assert!(start.elapsed() < Duration::from_secs(2));
    // The legacy public entry point is now bounded too, not just the new API.
    let compatibility_start = Instant::now();
    assert!(matches!(
        VerifiedWorker::new(&path, &"0".repeat(64)),
        Err(Failure::WorkerIdentityMismatch)
    ));
    assert!(compatibility_start.elapsed() < Duration::from_secs(2));
    let native = std::env::current_exe().unwrap();
    let expected = digest(&native);
    let validated =
        VerifiedWorker::with_deadline(&native, &expected, deadline(), &Cancellation::default())
            .unwrap();
    assert_eq!(validated.sha256(), expected);
    assert!(matches!(
        VerifiedWorker::with_deadline(&native, &expected, Instant::now(), &Cancellation::default()),
        Err(Failure::Timeout)
    ));
}
