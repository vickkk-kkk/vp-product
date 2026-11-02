//! Linux-only immutable executable snapshot. Hashing a pathname then spawning it
//! is NOT binary authentication: rename and same-inode writes can race that gap.
//! This managed runtime binds execution to a reviewed digest of sealed bytes.
use super::{Cancellation, Failure, VerifiedWorker};
use std::{process::Child, time::Instant};

/// Bounded construction shared by the compatibility constructor and explicit
/// deadline callers. Actual spawn captures and checks a fresh sealed snapshot.
impl VerifiedWorker {
    pub fn with_deadline(
        path: impl AsRef<std::path::Path>,
        expected_sha256: &str,
        deadline: Instant,
        cancel: &Cancellation,
    ) -> Result<Self, Failure> {
        let path = path.as_ref();
        if !path.is_absolute()
            || path.as_os_str().len() > 4096
            || expected_sha256.len() != 64
            || !expected_sha256.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(Failure::WorkerIdentityMismatch);
        }
        let worker = Self {
            path: path.to_path_buf(),
            sha256: expected_sha256.to_ascii_lowercase(),
        };
        // The same bounded regular-file/ELF/hash/seal checks as actual execution,
        // without invoking old lstat -> blocking open -> unbounded hash at all.
        let _validated = SealedExecutable::capture(&worker, deadline, cancel)?;
        Ok(worker)
    }
}

#[cfg(target_os = "linux")]
pub(crate) const MAX_WORKER_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
#[cfg(target_os = "linux")]
fn check(deadline: Instant, cancel: &Cancellation) -> Result<(), Failure> {
    if cancel.is_canceled() {
        Err(Failure::Canceled)
    } else if Instant::now() >= deadline {
        Err(Failure::Timeout)
    } else {
        Ok(())
    }
}
#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use rustix::fs::{
        fcntl_add_seals, fcntl_get_seals, memfd_create, open, MemfdFlags, Mode, OFlags, SealFlags,
    };
    use sha2::{Digest, Sha256};
    use std::{
        fs::File,
        io::{Read, Write},
        os::{
            fd::AsRawFd,
            unix::{fs::PermissionsExt, process::CommandExt},
        },
        process::{Command, Stdio},
    };
    use zeroize::Zeroizing;
    /// The fd is private and held through successful spawn. No API returns a
    /// pathname/Command that can outlive the fd, and no source path is reopened.
    pub(crate) struct SealedExecutable {
        file: File,
    }
    impl SealedExecutable {
        pub fn capture(
            worker: &VerifiedWorker,
            deadline: Instant,
            cancel: &Cancellation,
        ) -> Result<Self, Failure> {
            check(deadline, cancel)?;
            // NOFOLLOW prevents final symlink substitution; NONBLOCK prevents a
            // swapped FIFO from blocking open. Parent-directory replacement can
            // select different bytes, but cannot bypass the copied-byte digest.
            let source = open(
                &worker.path,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|_| Failure::WorkerIdentityMismatch)?;
            let mut source = File::from(source);
            let metadata = source
                .metadata()
                .map_err(|_| Failure::WorkerIdentityMismatch)?;
            if !metadata.is_file()
                || metadata.permissions().mode() & 0o022 != 0
                || !(64..=MAX_WORKER_EXECUTABLE_BYTES).contains(&metadata.len())
            {
                return Err(Failure::WorkerIdentityMismatch);
            }
            let mut header = Zeroizing::new([0_u8; 64]);
            source
                .read_exact(&mut *header)
                .map_err(|_| Failure::WorkerIdentityMismatch)?;
            validate_elf(&header)?;
            check(deadline, cancel)?;
            // Explicit EXEC requires Linux >=6.3. Unsupported/NOEXEC policy is a
            // typed refusal, NEVER a fallback to the original path or script.
            let fd = memfd_create(
                "vp-reviewed-worker",
                MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING | MemfdFlags::EXEC,
            )
            .map_err(|_| Failure::Unsupported)?;
            let mut file = File::from(fd);
            rustix::fs::fchmod(&file, Mode::from_raw_mode(0o555))
                .map_err(|_| Failure::Unsupported)?;
            file.write_all(&*header).map_err(|_| Failure::Io)?;
            let mut hash = Sha256::new();
            hash.update(&header[..]);
            let mut total = 64_u64;
            let mut buffer = Zeroizing::new([0_u8; 65536]);
            loop {
                check(deadline, cancel)?;
                let count = match source.read(&mut *buffer) {
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    other => other.map_err(|_| Failure::Io)?,
                };
                if count == 0 {
                    break;
                }
                total = total
                    .checked_add(count as u64)
                    .filter(|total| {
                        *total <= metadata.len() && *total <= MAX_WORKER_EXECUTABLE_BYTES
                    })
                    .ok_or(Failure::WorkerIdentityMismatch)?;
                hash.update(&buffer[..count]);
                file.write_all(&buffer[..count]).map_err(|_| Failure::Io)?;
            }
            if total != metadata.len() || format!("{:x}", hash.finalize()) != worker.sha256 {
                return Err(Failure::WorkerIdentityMismatch);
            }
            check(deadline, cancel)?;
            let seals = required_seals();
            fcntl_add_seals(&file, seals).map_err(|_| Failure::Unsupported)?;
            if !fcntl_get_seals(&file)
                .map_err(|_| Failure::Unsupported)?
                .contains(seals)
                || file.metadata().map_err(|_| Failure::Io)?.len() != total
                || !rustix::io::fcntl_getfd(&file)
                    .map_err(|_| Failure::Unsupported)?
                    .contains(rustix::io::FdFlags::CLOEXEC)
            {
                return Err(Failure::WorkerIdentityMismatch);
            }
            check(deadline, cancel)?;
            Ok(Self { file })
        }
        pub fn spawn(
            &self,
            arguments: &[&str],
            deadline: Instant,
            cancel: &Cancellation,
        ) -> Result<Child, Failure> {
            check(deadline, cancel)?;
            // Recheck the same held fd's seals, not the original pathname/hash.
            if !fcntl_get_seals(&self.file)
                .map_err(|_| Failure::Unsupported)?
                .contains(required_seals())
            {
                return Err(Failure::WorkerIdentityMismatch);
            }
            let path = format!("/proc/self/fd/{}", self.file.as_raw_fd());
            Command::new(path)
                .arg0("vp-sealed-worker")
                .args(arguments)
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|_| Failure::Io)
            // The borrow keeps the fd live until spawn completes. Linux resolves
            // the proc fd before exec closes CLOEXEC descriptors. ELF is mandatory;
            // a script interpreter would otherwise need to reopen a closed fd.
        }
    }
    fn required_seals() -> SealFlags {
        SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL | SealFlags::EXEC
    }
    fn validate_elf(header: &[u8; 64]) -> Result<(), Failure> {
        let machine = match std::env::consts::ARCH {
            "x86_64" => 62,
            "aarch64" => 183,
            _ => return Err(Failure::Unsupported),
        };
        // ELF64 little-endian native Linux executable/shared-object (PIE).
        if &header[..4] != b"\x7fELF"
            || header[4] != 2
            || header[5] != 1
            || header[6] != 1
            || ![0, 3].contains(&header[7])
            || ![2, 3].contains(&u16::from_le_bytes([header[16], header[17]]))
            || u16::from_le_bytes([header[18], header[19]]) != machine
            || u32::from_le_bytes(
                header[20..24]
                    .try_into()
                    .map_err(|_| Failure::WorkerIdentityMismatch)?,
            ) != 1
            || u16::from_le_bytes([header[52], header[53]]) != 64
        {
            return Err(Failure::WorkerIdentityMismatch);
        }
        Ok(())
    }
    #[cfg(test)]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    mod tests {
        include!("sealed_executable_tests.rs");
    }
}
#[cfg(target_os = "linux")]
pub(crate) use linux::SealedExecutable;
#[cfg(not(target_os = "linux"))]
pub(crate) struct SealedExecutable;
#[cfg(not(target_os = "linux"))]
impl SealedExecutable {
    pub fn capture(_: &VerifiedWorker, _: Instant, _: &Cancellation) -> Result<Self, Failure> {
        Err(Failure::Unsupported)
    }
    pub fn spawn(&self, _: &[&str], _: Instant, _: &Cancellation) -> Result<Child, Failure> {
        Err(Failure::Unsupported)
    }
}
