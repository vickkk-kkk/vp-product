//! Audited C-pointer boundary. All exported layouts mirror vp_adapter.h.
//! Caller guarantees alignment, validity/lifetimes, and no new calls racing
//! destroy (header contract). This module alone dereferences foreign pointers.
use super::*;
use std::{
    ffi::c_void,
    io,
    mem::size_of,
    net::SocketAddr,
    panic::{catch_unwind, AssertUnwindSafe},
    ptr,
};
pub const OK: i32 = 0;
pub const INVALID_ARGUMENT: i32 = 1;
pub const INVALID_UTF8: i32 = 2;
pub const TOO_LARGE: i32 = 3;
pub const ABI_INCOMPATIBLE: i32 = 4;
pub const UNSUPPORTED: i32 = 5;
pub const HOOK_REQUIRED: i32 = 6;
pub const TIMEOUT: i32 = 8;
pub const CLOSED: i32 = 9;
pub const BUSY: i32 = 10;
pub const INTERNAL: i32 = 11;
const MAX_BYTES: usize = 1_048_576;
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Bytes {
    pub data: *const u8,
    pub len: u64,
}
#[repr(C)]
pub struct OwnedBytes {
    pub data: *mut u8,
    pub len: u64,
    pub allocation: *mut c_void,
}
impl Default for OwnedBytes {
    fn default() -> Self {
        Self {
            data: ptr::null_mut(),
            len: 0,
            allocation: ptr::null_mut(),
        }
    }
}
#[repr(C)]
pub struct ConnectContext {
    pub struct_size: u32,
    pub protocol: u32,
    pub purpose: u32,
    pub reserved: u32,
    pub socket_handle: u64,
    pub destination_host_utf8: Bytes,
    pub destination_port: u16,
    pub reserved16: u16,
    pub reserved32: u32,
}
type Before = unsafe extern "C" fn(*mut c_void, *const ConnectContext) -> i32;
type NetworkSnapshot = unsafe extern "C" fn(*mut c_void, *mut u8, u64, *mut u64) -> i32;
#[repr(C)]
#[derive(Clone, Copy)]
pub struct HostCallbacks {
    pub struct_size: u32,
    pub reserved: u32,
    pub user_context: *mut c_void,
    pub before_connect: Option<Before>,
    pub network_snapshot: Option<NetworkSnapshot>,
}
#[repr(C)]
pub struct CreateOptions {
    pub struct_size: u32,
    pub abi_major: u16,
    pub abi_minor: u16,
    pub platform_mode: u32,
    pub reserved: u32,
    pub available_hooks: u64,
    pub required_hooks: u64,
    pub callbacks: *const HostCallbacks,
    pub storage_root_utf8: Bytes,
    pub event_queue_capacity: u32,
    pub packet_queue_capacity: u32,
    pub android_duplicate_tun_fd: i64,
    pub packet_mtu: u32,
    pub reserved_tail: u32,
}
#[repr(C)]
pub struct Packet {
    pub bytes: Bytes,
    pub family: u32,
    pub reserved: u32,
}
#[repr(C)]
pub struct PacketBatch {
    pub struct_size: u32,
    pub count: u32,
    pub packets: *const Packet,
}
#[repr(C)]
pub struct OwnedPacketBatch {
    pub struct_size: u32,
    pub count: u32,
    pub packets: *const Packet,
    pub allocation: *mut c_void,
}
#[derive(Clone)]
pub(super) struct Callbacks {
    before: Before,
    context: usize,
    dns: Vec<SocketAddr>,
    bootstrap_host: Option<String>,
    failures: Arc<AtomicU64>,
}
impl Callbacks {
    pub(super) fn failures(&self) -> u64 {
        self.failures.load(Ordering::Acquire)
    }
    pub(super) fn with_bootstrap(&self, dns: Vec<SocketAddr>, host: String) -> Self {
        Self {
            before: self.before,
            context: self.context,
            dns,
            bootstrap_host: Some(host),
            failures: self.failures.clone(),
        }
    }
}
impl vp_core::host_network::HostNetwork for Callbacks {
    fn before_connect(
        &self,
        socket: u64,
        protocol: vp_core::host_network::Protocol,
        destination: SocketAddr,
        purpose: vp_core::host_network::Purpose,
    ) -> io::Result<()> {
        use vp_core::host_network::{Protocol, Purpose};
        let host = destination.ip().to_string();
        let c = ConnectContext {
            struct_size: size_of::<ConnectContext>() as u32,
            protocol: match protocol {
                Protocol::Tcp => 1,
                Protocol::Udp => 2,
            },
            purpose: match purpose {
                Purpose::Proxy => 1,
                Purpose::Dns => 2,
                Purpose::Bootstrap => 3,
                Purpose::Subscription => 4,
                Purpose::ConnectivityCheck => 5,
            },
            reserved: 0,
            socket_handle: socket,
            destination_host_utf8: Bytes {
                data: host.as_ptr(),
                len: host.len() as u64,
            },
            destination_port: destination.port(),
            reserved16: 0,
            reserved32: 0,
        };
        // SAFETY: copied callback/context remain valid until successful destroy;
        // context and borrowed host bytes are alive for this synchronous invocation.
        let status = unsafe { (self.before)(self.context as *mut c_void, &c) };
        if status == OK {
            Ok(())
        } else {
            self.failures.fetch_add(1, Ordering::AcqRel);
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "host denied socket protection",
            ))
        }
    }
    fn bootstrap_host(&self) -> Option<String> {
        self.bootstrap_host.clone()
    }
    fn dns_servers(&self) -> Vec<SocketAddr> {
        self.dns.clone()
    }
}
fn guard(f: impl FnOnce() -> Result<(), i32>) -> i32 {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => OK,
        Ok(Err(code)) => code,
        Err(_) => INTERNAL,
    }
}
unsafe fn span<'a>(b: Bytes) -> Result<&'a [u8], i32> {
    if b.len > MAX_BYTES as u64 {
        return Err(TOO_LARGE);
    }
    if b.len == 0 {
        return if b.data.is_null() {
            Ok(&[])
        } else {
            Err(INVALID_ARGUMENT)
        };
    }
    if b.data.is_null() {
        return Err(INVALID_ARGUMENT);
    } // SAFETY: ABI caller provides a readable borrowed span of stated length.
    Ok(unsafe { std::slice::from_raw_parts(b.data, b.len as usize) })
}
unsafe fn empty(out: *mut OwnedBytes) -> Result<(), i32> {
    if out.is_null() {
        return Err(INVALID_ARGUMENT);
    } // SAFETY: ABI caller provides aligned writable output storage.
    unsafe { out.write(OwnedBytes::default()) };
    Ok(())
}
unsafe fn output(out: *mut OwnedBytes, data: Vec<u8>) -> Result<(), i32> {
    if data.len() > MAX_BYTES {
        return Err(TOO_LARGE);
    }
    let mut allocation = Box::new(data);
    let value = OwnedBytes {
        data: allocation.as_mut_ptr(),
        len: allocation.len() as u64,
        allocation: Box::into_raw(allocation).cast(),
    };
    unsafe { out.write(value) };
    Ok(())
}
struct Active<'a>(&'a Handle);
impl Drop for Active<'_> {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
    }
}
unsafe fn enter<'a>(handle: *mut Handle) -> Result<Active<'a>, i32> {
    if handle.is_null() {
        return Err(INVALID_ARGUMENT);
    } // SAFETY: caller owns a live handle and must not race new calls with destroy.
    let h = unsafe { &*handle };
    h.active.fetch_add(1, Ordering::AcqRel);
    let guard = Active(h);
    if h.closing.load(Ordering::Acquire) {
        return Err(CLOSED);
    }
    Ok(guard)
}

/// # Safety
/// `out_json` points to writable empty ABI-owned output storage.
#[no_mangle]
pub unsafe extern "C" fn vp_adapter_abi_info(out_json: *mut OwnedBytes) -> i32 {
    guard(|| {
        unsafe { empty(out_json)? };
        let build = crate::inspect_build().map_err(|_| INTERNAL)?;
        let info = json!({
            "buildInspection": build,
            "abiMajor": ABI_MAJOR,
            "abiMinor": ABI_MINOR,
            "schemaVersion": SCHEMA_VERSION,
            "connectPayloadVersions": [config::CONNECT_PAYLOAD_VERSION],
            "engine": "vp_core",
            "mobileRuntime": "in_process",
            "platformModes": [2],
            "requiredHooks": 1,
            "packetFlow": false,
            "maximumControlBytes": MAX_BYTES
        });
        unsafe { output(out_json, serde_json::to_vec(&info).map_err(|_| INTERNAL)?) }
    })
}
/// Pure preflight before permission or FD acquisition. Does not construct a
/// controller/runtime or open any socket. Output never includes credentials.
/// # Safety
/// Input is a borrowed readable span and output is aligned writable empty storage.
#[no_mangle]
pub unsafe extern "C" fn vp_adapter_validate_connect(
    payload: Bytes,
    out_json: *mut OwnedBytes,
) -> i32 {
    guard(|| {
        unsafe { empty(out_json)? };
        let bytes = unsafe { span(payload)? };
        std::str::from_utf8(bytes).map_err(|_| INVALID_UTF8)?;
        let validation = match serde_json::from_slice::<config::Connect>(bytes) {
            Ok(input) => input.build().map(|built| built.outbound.support_udp()),
            Err(_) => Err(ProductError::new(
                ErrorCode::ConfigInvalid,
                ErrorStage::Decode,
            )),
        };
        let result = match validation {
            Ok(udp) => {
                json!({"schemaVersion":SCHEMA_VERSION,"valid":true,"error":null,"supportedTraffic":if udp { vec!["tcp","udp"] } else { vec!["tcp"] }})
            }
            Err(error) => json!({"schemaVersion":SCHEMA_VERSION,"valid":false,"error":error}),
        };
        unsafe { output(out_json, serde_json::to_vec(&result).map_err(|_| INTERNAL)?) }
    })
}

/// # Safety
/// Pointers/FD transfer must follow contracts/abi/vp_adapter.h. Callback lifetimes
/// extend through successful destroy, including failed/closing state.
#[no_mangle]
pub unsafe extern "C" fn vp_adapter_create(
    options: *const CreateOptions,
    out: *mut *mut Handle,
) -> i32 {
    guard(|| {
        if !out.is_null() {
            unsafe { out.write(ptr::null_mut()) }
        }
        if options.is_null() {
            return Err(INVALID_ARGUMENT);
        }
        // Read only the size prefix before touching fields outside shorter layouts.
        let size = unsafe { ptr::read(options.cast::<u32>()) };
        if size < (size_of::<CreateOptions>() as u32) {
            return Err(ABI_INCOMPATIBLE);
        }
        let o = unsafe { &*options };
        // FD is consumed BEFORE every remaining validation, including null out.
        let fd = if o.platform_mode == 2 && o.android_duplicate_tun_fd >= 0 {
            Some(fd::consume(o.android_duplicate_tun_fd).map_err(|_| INVALID_ARGUMENT)?)
        } else {
            None
        };
        if out.is_null() {
            return Err(INVALID_ARGUMENT);
        }
        if o.abi_major != ABI_MAJOR || o.abi_minor > ABI_MINOR {
            return Err(ABI_INCOMPATIBLE);
        }
        if o.reserved != 0 || o.reserved_tail != 0 {
            return Err(INVALID_ARGUMENT);
        }
        if o.platform_mode != 2 {
            return Err(UNSUPPORTED);
        }
        if o.available_hooks & !3 != 0 || o.required_hooks & !3 != 0 {
            return Err(HOOK_REQUIRED);
        }
        if o.available_hooks & o.required_hooks != o.required_hooks || o.available_hooks & 1 == 0 {
            return Err(HOOK_REQUIRED);
        }
        if o.required_hooks & 2 != 0 {
            return Err(UNSUPPORTED);
        }
        if !(16..=4096).contains(&o.event_queue_capacity)
            || !(1..=4096).contains(&o.packet_queue_capacity)
            || !(1280..=65535).contains(&o.packet_mtu)
        {
            return Err(INVALID_ARGUMENT);
        }
        let root =
            std::str::from_utf8(unsafe { span(o.storage_root_utf8)? }).map_err(|_| INVALID_UTF8)?;
        if !root.is_empty()
            && (!std::path::Path::new(root).is_absolute() || root.as_bytes().contains(&0))
        {
            return Err(INVALID_ARGUMENT);
        }
        if o.callbacks.is_null() {
            return Err(HOOK_REQUIRED);
        }
        let callbacks_size = unsafe { ptr::read(o.callbacks.cast::<u32>()) };
        if callbacks_size < size_of::<HostCallbacks>() as u32 {
            return Err(ABI_INCOMPATIBLE);
        }
        let c = unsafe { *o.callbacks };
        if c.reserved != 0 {
            return Err(INVALID_ARGUMENT);
        }
        let before = c.before_connect.ok_or(HOOK_REQUIRED)?;
        let fd = fd.ok_or(INVALID_ARGUMENT)?;
        let handle = Handle::create(
            fd,
            o.packet_mtu as u16,
            o.event_queue_capacity as usize,
            Callbacks {
                before,
                context: c.user_context as usize,
                dns: vec![],
                bootstrap_host: None,
                failures: Arc::new(AtomicU64::new(0)),
            },
        )?;
        unsafe { out.write(Box::into_raw(Box::new(handle))) };
        Ok(())
    })
}
/// # Safety
/// Live handle and borrowed readable request span; output initialized empty.
#[no_mangle]
pub unsafe extern "C" fn vp_adapter_request(
    handle: *mut Handle,
    request: Bytes,
    out_json: *mut OwnedBytes,
) -> i32 {
    guard(|| {
        unsafe { empty(out_json)? };
        let active = unsafe { enter(handle)? };
        let bytes = unsafe { span(request)? };
        std::str::from_utf8(bytes).map_err(|_| INVALID_UTF8)?;
        let result = active.0.request(bytes)?;
        unsafe { output(out_json, result) }
    })
}
/// # Safety
/// A live handle, one background reader, and writable empty output.
#[no_mangle]
pub unsafe extern "C" fn vp_adapter_next_event(
    handle: *mut Handle,
    timeout_ms: u32,
    out_json: *mut OwnedBytes,
) -> i32 {
    guard(|| {
        unsafe { empty(out_json)? };
        if timeout_ms > 60000 {
            return Err(INVALID_ARGUMENT);
        }
        let active = unsafe { enter(handle)? };
        unsafe {
            output(
                out_json,
                active
                    .0
                    .next_event(Duration::from_millis(timeout_ms as u64))?,
            )
        }
    })
}
/// # Safety
/// Handle/input must be valid. Android uses its FD, never this Apple queue API.
#[no_mangle]
pub unsafe extern "C" fn vp_adapter_packet_write(
    handle: *mut Handle,
    _input: *const PacketBatch,
) -> i32 {
    guard(|| {
        let _active = unsafe { enter(handle)? };
        Err(UNSUPPORTED)
    })
}
/// # Safety
/// Output is aligned writable storage. Apple packetFlow is not yet implemented.
#[no_mangle]
pub unsafe extern "C" fn vp_adapter_packet_read(
    handle: *mut Handle,
    _timeout_ms: u32,
    out: *mut OwnedPacketBatch,
) -> i32 {
    guard(|| {
        if out.is_null() {
            return Err(INVALID_ARGUMENT);
        }
        unsafe {
            out.write(OwnedPacketBatch {
                struct_size: 0,
                count: 0,
                packets: ptr::null(),
                allocation: ptr::null_mut(),
            })
        };
        let _active = unsafe { enter(handle)? };
        Err(UNSUPPORTED)
    })
}
/// # Safety
/// Host first stops issuing calls and joins pumps. BUSY/TIMEOUT preserves handle;
/// retry destroy only. Only OK invalidates. NULL is accepted.
#[no_mangle]
pub unsafe extern "C" fn vp_adapter_destroy(handle: *mut Handle) -> i32 {
    guard(|| {
        if handle.is_null() {
            return Ok(());
        }
        let status = unsafe { &*handle }.close();
        if status != OK {
            return Err(status);
        } // SAFETY: no active calls remain and worker/runtime joined; unique owning token.
        unsafe { drop(Box::from_raw(handle)) };
        Ok(())
    })
}
/// # Safety
/// Original owning output only, not copied. Resets fields before dropping token.
#[no_mangle]
pub unsafe extern "C" fn vp_adapter_bytes_free(bytes: *mut OwnedBytes) {
    let _ = guard(|| {
        if bytes.is_null() {
            return Ok(());
        }
        let owned = unsafe { ptr::replace(bytes, OwnedBytes::default()) };
        if !owned.allocation.is_null() {
            // SAFETY: allocation token originated from Box<Vec<u8>> in output().
            unsafe { drop(Box::from_raw(owned.allocation.cast::<Vec<u8>>())) }
        }
        Ok(())
    });
}
/// # Safety
/// Must be the original provider-owned output (currently always empty).
#[no_mangle]
pub unsafe extern "C" fn vp_adapter_packets_free(packets: *mut OwnedPacketBatch) {
    let _ = guard(|| {
        if packets.is_null() {
            return Ok(());
        }
        let p = unsafe { &mut *packets };
        if !p.allocation.is_null() {
            return Err(INVALID_ARGUMENT);
        }
        *p = OwnedPacketBatch {
            struct_size: 0,
            count: 0,
            packets: ptr::null(),
            allocation: ptr::null_mut(),
        };
        Ok(())
    });
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Fixture/setup failures must fail these tests immediately.
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, IntoRawFd};
    unsafe extern "C" fn protect(_: *mut c_void, _: *const ConnectContext) -> i32 {
        OK
    }
    fn options(fd: i32, callbacks: &HostCallbacks) -> CreateOptions {
        CreateOptions {
            struct_size: size_of::<CreateOptions>() as u32,
            abi_major: 1,
            abi_minor: 0,
            platform_mode: 2,
            reserved: 0,
            available_hooks: 1,
            required_hooks: 1,
            callbacks,
            storage_root_utf8: Bytes {
                data: ptr::null(),
                len: 0,
            },
            event_queue_capacity: 16,
            packet_queue_capacity: 16,
            android_duplicate_tun_fd: fd as i64,
            packet_mtu: 1500,
            reserved_tail: 0,
        }
    }
    fn callbacks() -> HostCallbacks {
        HostCallbacks {
            struct_size: size_of::<HostCallbacks>() as u32,
            reserved: 0,
            user_context: ptr::null_mut(),
            before_connect: Some(protect),
            network_snapshot: None,
        }
    }
    fn create() -> (*mut Handle, std::os::unix::net::UnixDatagram) {
        let (device, host) = std::os::unix::net::UnixDatagram::pair().unwrap();
        let callbacks = callbacks();
        let options = options(device.into_raw_fd(), &callbacks);
        let mut handle = ptr::null_mut();
        assert_eq!(unsafe { vp_adapter_create(&options, &mut handle) }, OK);
        (handle, host)
    }
    unsafe fn request(handle: *mut Handle, value: Value) -> Value {
        let data = serde_json::to_vec(&value).unwrap();
        let mut out = OwnedBytes::default();
        assert_eq!(
            unsafe {
                vp_adapter_request(
                    handle,
                    Bytes {
                        data: data.as_ptr(),
                        len: data.len() as u64,
                    },
                    &mut out,
                )
            },
            OK
        );
        let result = serde_json::from_slice(unsafe {
            std::slice::from_raw_parts(out.data, out.len as usize)
        })
        .unwrap();
        unsafe { vp_adapter_bytes_free(&mut out) };
        result
    }
    fn command(method: &str, expected: u64, key: &str) -> Value {
        json!({"schemaVersion":1,"requestId":"test-request","idempotencyKey":key,"expectedRevision":expected,"method":method,"payload":{}})
    }
    #[test]
    fn abi_output_is_owned_and_same_struct_double_free_is_safe() {
        let mut out = OwnedBytes::default();
        assert_eq!(unsafe { vp_adapter_abi_info(&mut out) }, OK);
        assert!(out.len > 0);
        let value: Value = serde_json::from_slice(unsafe {
            std::slice::from_raw_parts(out.data, out.len as usize)
        })
        .unwrap();
        assert_eq!(value["engine"], "vp_core");
        assert_eq!(value["connectPayloadVersions"], json!([2]));
        unsafe {
            vp_adapter_bytes_free(&mut out);
            vp_adapter_bytes_free(&mut out)
        }
        assert!(out.data.is_null());
        assert!(out.allocation.is_null());
        assert_eq!(out.len, 0);
    }
    #[test]
    fn failed_create_consumes_duplicate_but_not_original() {
        let (original, _) = std::os::unix::net::UnixDatagram::pair().unwrap();
        let duplicate = original.try_clone().unwrap().into_raw_fd();
        let cb = callbacks();
        let mut options = options(duplicate, &cb);
        options.abi_major = 9;
        let mut handle = ptr::null_mut();
        assert_eq!(
            unsafe { vp_adapter_create(&options, &mut handle) },
            ABI_INCOMPATIBLE
        );
        assert!(handle.is_null());
        assert_eq!(unsafe { libc::fcntl(duplicate, libc::F_GETFD) }, -1);
        assert!(unsafe { libc::fcntl(original.as_raw_fd(), libc::F_GETFD) } >= 0);
    }
    #[test]
    fn null_output_also_consumes_transferred_fd() {
        let (original, _) = std::os::unix::net::UnixDatagram::pair().unwrap();
        let duplicate = original.try_clone().unwrap().into_raw_fd();
        let cb = callbacks();
        let options = options(duplicate, &cb);
        assert_eq!(
            unsafe { vp_adapter_create(&options, ptr::null_mut()) },
            INVALID_ARGUMENT
        );
        assert_eq!(unsafe { libc::fcntl(duplicate, libc::F_GETFD) }, -1);
    }
    #[test]
    fn short_prefix_never_reads_or_consumes_fd() {
        let short = 4u32;
        let mut handle = ptr::null_mut();
        assert_eq!(
            unsafe { vp_adapter_create((&short as *const u32).cast(), &mut handle) },
            ABI_INCOMPATIBLE
        );
        assert!(handle.is_null());
    }
    #[test]
    fn mandatory_protection_missing_fails_closed() {
        let (device, _) = std::os::unix::net::UnixDatagram::pair().unwrap();
        let cb = callbacks();
        let mut options = options(device.into_raw_fd(), &cb);
        options.available_hooks = 0;
        let mut handle = ptr::null_mut();
        assert_eq!(
            unsafe { vp_adapter_create(&options, &mut handle) },
            HOOK_REQUIRED
        );
    }
    #[test]
    fn idle_snapshot_is_canonical_not_connected() {
        let (handle, _host) = create();
        let result = unsafe { request(handle, command("snapshot", 0, "key")) };
        let snapshot: RuntimeSnapshot = serde_json::from_value(result["result"].clone()).unwrap();
        assert_eq!(snapshot.phase, RuntimePhase::Idle);
        assert!(!snapshot.connection_verified());
        assert_eq!(unsafe { vp_adapter_destroy(handle) }, OK);
    }
    #[test]
    fn strict_utf8_json_and_bounds_outputs_remain_empty() {
        let (handle, _host) = create();
        let mut out = OwnedBytes::default();
        assert_eq!(
            unsafe {
                vp_adapter_request(
                    handle,
                    Bytes {
                        data: ptr::null(),
                        len: u64::MAX,
                    },
                    &mut out,
                )
            },
            TOO_LARGE
        );
        assert!(out.data.is_null());
        let invalid = [0xff];
        assert_eq!(
            unsafe {
                vp_adapter_request(
                    handle,
                    Bytes {
                        data: invalid.as_ptr(),
                        len: 1,
                    },
                    &mut out,
                )
            },
            INVALID_UTF8
        );
        assert!(out.allocation.is_null());
        let invalid = b"{}";
        assert_eq!(
            unsafe {
                vp_adapter_request(
                    handle,
                    Bytes {
                        data: invalid.as_ptr(),
                        len: 2,
                    },
                    &mut out,
                )
            },
            INVALID_ARGUMENT
        );
        assert_eq!(unsafe { vp_adapter_destroy(handle) }, OK);
    }
    #[test]
    fn stop_before_start_is_idempotent_and_generation_is_reserved() {
        let (handle, _host) = create();
        let cmd = command("disconnect", 0, "stop-1");
        let first = unsafe { request(handle, cmd.clone()) };
        assert_eq!(first["result"]["generation"], 1);
        let retry = unsafe { request(handle, cmd) };
        assert_eq!(retry, first);
        let conflict = unsafe { request(handle, command("operation_cancel", 0, "stop-1")) };
        assert_eq!(conflict["error"]["code"], "IDEMPOTENCY_CONFLICT");
        assert_eq!(unsafe { vp_adapter_destroy(handle) }, OK);
    }
    #[test]
    fn overflow_emits_resync_and_monotonic_sequence() {
        let (handle, _host) = create();
        let h = unsafe { &*handle };
        for _ in 0..17 {
            h.shared.update(Revision::ZERO, |_| {});
        }
        let mut out = OwnedBytes::default();
        assert_eq!(unsafe { vp_adapter_next_event(handle, 0, &mut out) }, OK);
        let e: RuntimeEvent = serde_json::from_slice(unsafe {
            std::slice::from_raw_parts(out.data, out.len as usize)
        })
        .unwrap();
        assert!(matches!(
            e.payload,
            RuntimeEventPayload::ResyncRequired { .. }
        ));
        assert_eq!(e.sequence.get(), 17);
        unsafe { vp_adapter_bytes_free(&mut out) };
        assert_eq!(unsafe { vp_adapter_destroy(handle) }, OK);
    }
    #[test]
    fn destroy_unblocks_existing_event_reader_and_requires_retry() {
        let (handle, _host) = create();
        let address = handle as usize;
        let reader = std::thread::spawn(move || {
            let mut out = OwnedBytes::default();
            unsafe { vp_adapter_next_event(address as *mut Handle, 60000, &mut out) }
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while unsafe { &*handle }.active.load(Ordering::Acquire) == 0 {
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert_eq!(unsafe { vp_adapter_destroy(handle) }, BUSY);
        assert_eq!(reader.join().unwrap(), CLOSED);
        assert_eq!(unsafe { vp_adapter_destroy(handle) }, OK);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Fixture/setup failures must fail these tests immediately.
mod preflight_tests {
    use super::*;
    #[test]
    fn pure_preflight_returns_typed_failure_and_never_echoes_secret() {
        let input = br#"{"credential":{"kind":"password","value":"MUST_NOT_ECHO"}}"#;
        let mut out = OwnedBytes::default();
        assert_eq!(
            unsafe {
                vp_adapter_validate_connect(
                    Bytes {
                        data: input.as_ptr(),
                        len: input.len() as u64,
                    },
                    &mut out,
                )
            },
            OK
        );
        let bytes = unsafe { std::slice::from_raw_parts(out.data, out.len as usize) };
        assert!(!std::str::from_utf8(bytes)
            .unwrap()
            .contains("MUST_NOT_ECHO"));
        let result: Value = serde_json::from_slice(bytes).unwrap();
        assert_eq!(result["valid"], false);
        let _: ProductError = serde_json::from_value(result["error"].clone()).unwrap();
        unsafe { vp_adapter_bytes_free(&mut out) };
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Fixture/setup failures must fail these tests immediately.
mod packet_runtime_tests {
    use super::*;
    use std::{
        io::{Read, Write},
        os::fd::IntoRawFd,
    };
    unsafe extern "C" fn protect(_: *mut c_void, _: *const ConnectContext) -> i32 {
        OK
    }
    fn checksum(packet: &[u8]) -> u16 {
        let sum = packet
            .chunks(2)
            .map(|x| u16::from_be_bytes([x[0], *x.get(1).unwrap_or(&0)]) as u32)
            .sum::<u32>();
        let sum = (sum & 65535) + (sum >> 16);
        !((sum & 65535) + (sum >> 16)) as u16
    }
    unsafe fn request(handle: *mut Handle, cmd: Value) -> Value {
        let input = serde_json::to_vec(&cmd).unwrap();
        let mut output = OwnedBytes::default();
        assert_eq!(
            unsafe {
                vp_adapter_request(
                    handle,
                    Bytes {
                        data: input.as_ptr(),
                        len: input.len() as u64,
                    },
                    &mut output,
                )
            },
            OK
        );
        let value = serde_json::from_slice(unsafe {
            std::slice::from_raw_parts(output.data, output.len as usize)
        })
        .unwrap();
        unsafe { vp_adapter_bytes_free(&mut output) };
        value
    }
    #[test]
    fn real_vp_core_packet_loop_relays_udp_and_closes_duplicate_on_stop() {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        tcp.set_nonblocking(true).unwrap();
        let port = tcp.local_addr().unwrap().port();
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        udp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let relay_port = udp.local_addr().unwrap().port();
        let peer = std::thread::spawn(move || {
            let end = std::time::Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match tcp.accept() {
                    Ok((s, _)) => break s,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        assert!(std::time::Instant::now() < end, "core did not dial peer");
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("{e}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [5, 1, 2]);
            stream.write_all(&[5, 2]).unwrap();
            let mut auth = [0; 2];
            stream.read_exact(&mut auth).unwrap();
            assert_eq!(auth, [1, 4]);
            let mut user = [0; 4];
            stream.read_exact(&mut user).unwrap();
            assert_eq!(&user, b"test");
            let mut len = [0];
            stream.read_exact(&mut len).unwrap();
            let mut password = vec![0; len[0] as usize];
            stream.read_exact(&mut password).unwrap();
            assert_eq!(&password, b"test-only");
            stream.write_all(&[1, 0]).unwrap();
            let mut request = [0; 10];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(request, [5, 3, 0, 1, 0, 0, 0, 0, 0, 0]);
            let mut response = vec![5, 0, 0, 1, 127, 0, 0, 1];
            response.extend(relay_port.to_be_bytes());
            stream.write_all(&response).unwrap();
            let mut packet = [0; 1500];
            let (n, from) = udp.recv_from(&mut packet).unwrap();
            assert_eq!(&packet[..4], &[0, 0, 0, 1]);
            assert_eq!(&packet[10..n], b"vp-tun-proof");
            udp.send_to(&packet[..n], from).unwrap();
            let mut byte = [0];
            assert_eq!(
                stream.read(&mut byte).unwrap(),
                0,
                "stop must close SOCKS control socket"
            );
        });
        let (device, host) = std::os::unix::net::UnixDatagram::pair().unwrap();
        host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let duplicate = device.into_raw_fd();
        let callbacks = HostCallbacks {
            struct_size: size_of::<HostCallbacks>() as u32,
            reserved: 0,
            user_context: ptr::null_mut(),
            before_connect: Some(protect),
            network_snapshot: None,
        };
        let options = CreateOptions {
            struct_size: size_of::<CreateOptions>() as u32,
            abi_major: 1,
            abi_minor: 1,
            platform_mode: 2,
            reserved: 0,
            available_hooks: 1,
            required_hooks: 1,
            callbacks: &callbacks,
            storage_root_utf8: Bytes {
                data: ptr::null(),
                len: 0,
            },
            event_queue_capacity: 16,
            packet_queue_capacity: 16,
            android_duplicate_tun_fd: duplicate as i64,
            packet_mtu: 1500,
            reserved_tail: 0,
        };
        let mut handle = ptr::null_mut();
        assert_eq!(unsafe { vp_adapter_create(&options, &mut handle) }, OK);
        let payload = json!({"schemaVersion":2,"node":{"schemaVersion":1,"id":"node-test","name":"Test","endpoint":{"host":"127.0.0.1","port":port},"protocol":{"kind":"socks5"},"transport":{"kind":"tcp"},"security":{"kind":"none"},"credentialRef":"secret:test","requirements":[],"sourceRef":null},"credential":{"kind":"username_password","username":"test","password":"test-only"},"configRevision":1,"dns":{"bootstrapServers":["127.0.0.1:5353"],"user":{"route":"selected_proxy","servers":["127.0.0.1:5353"]}}});
        let result = unsafe {
            request(
                handle,
                json!({"schemaVersion":1,"requestId":"connect-test","idempotencyKey":"connect-test","expectedRevision":0,"method":"connect","payload":payload}),
            )
        };
        assert_eq!(result["result"]["accepted"], true);
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        let length = 40u16;
        packet[2..4].copy_from_slice(&length.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 89, 0, 1]);
        packet[16..20].copy_from_slice(&[127, 0, 0, 1]);
        let check = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&check.to_be_bytes());
        packet[20..22].copy_from_slice(&43000u16.to_be_bytes());
        packet[22..24].copy_from_slice(&7777u16.to_be_bytes());
        packet[24..26].copy_from_slice(&20u16.to_be_bytes());
        packet.extend_from_slice(b"vp-tun-proof");
        host.send(&packet).unwrap();
        let mut reply = [0; 1500];
        let n = host.recv(&mut reply).unwrap();
        assert_eq!(&reply[n - 12..n], b"vp-tun-proof");
        let end = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            let snapshot = unsafe { &*handle }.shared.snapshot();
            if snapshot.connection_verified() {
                break;
            }
            assert!(
                std::time::Instant::now() < end,
                "forwarding evidence was not observed: {:?}",
                snapshot.phase
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(unsafe { vp_adapter_destroy(handle) }, OK);
        assert_eq!(unsafe { libc::fcntl(duplicate, libc::F_GETFD) }, -1);
        peer.join().unwrap();
    }
    unsafe extern "C" fn deny(_: *mut c_void, _: *const ConnectContext) -> i32 {
        12
    }
    #[test]
    fn denied_socket_is_reported_as_permission_failure_not_stuck_verifying() {
        let peer = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        peer.set_nonblocking(true).unwrap();
        let port = peer.local_addr().unwrap().port();
        let (device, host) = std::os::unix::net::UnixDatagram::pair().unwrap();
        let handle = Handle::create(
            device.into(),
            1500,
            16,
            Callbacks {
                before: deny,
                context: 0,
                dns: vec![],
                bootstrap_host: None,
                failures: Arc::new(AtomicU64::new(0)),
            },
        )
        .unwrap();
        let payload = json!({"schemaVersion":2,"node":{"schemaVersion":1,"id":"denied-node","name":"Test","endpoint":{"host":"127.0.0.1","port":port},"protocol":{"kind":"socks5"},"transport":{"kind":"tcp"},"security":{"kind":"none"},"credentialRef":"secret:test","requirements":[],"sourceRef":null},"credential":{"kind":"username_password","username":"test","password":"test-only"},"configRevision":1,"dns":{"bootstrapServers":["127.0.0.1:5353"],"user":{"route":"selected_proxy","servers":["127.0.0.1:5353"]}}});
        let cmd = json!({"schemaVersion":1,"requestId":"deny","idempotencyKey":"deny","expectedRevision":0,"method":"connect","payload":payload});
        let result: Value =
            serde_json::from_slice(&handle.request(&serde_json::to_vec(&cmd).unwrap()).unwrap())
                .unwrap();
        assert_eq!(result["result"]["accepted"], true);
        let mut packet = vec![
            0x45, 0, 0, 32, 0, 0, 0, 0, 64, 17, 0, 0, 10, 89, 0, 1, 127, 0, 0, 1, 0xa7, 0xf8, 0x1e,
            0x61, 0, 12, 0, 0, b't', b'e', b's', b't',
        ];
        let check = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&check.to_be_bytes());
        host.send(&packet).unwrap();
        let end = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            let snapshot = handle.shared.snapshot();
            if snapshot.phase == RuntimePhase::Failed {
                assert_eq!(snapshot.error.unwrap().code, ErrorCode::PermissionDenied);
                break;
            }
            assert!(std::time::Instant::now() < end);
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(matches!(peer.accept(),Err(e) if e.kind()==io::ErrorKind::WouldBlock));
        assert_eq!(handle.close(), OK);
    }
    #[test]
    fn original_connect_bytes_reject_nested_duplicates_before_device_or_generation_action() {
        use std::os::fd::AsRawFd;
        let (device, _host) = std::os::unix::net::UnixDatagram::pair().unwrap();
        let raw = device.as_raw_fd();
        let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
        let calls = Arc::new(AtomicU64::new(0));
        unsafe extern "C" fn count(context: *mut c_void, _: *const ConnectContext) -> i32 {
            // SAFETY: the test keeps its Arc allocation alive through close().
            unsafe { &*context.cast::<AtomicU64>() }.fetch_add(1, Ordering::SeqCst);
            OK
        }
        let handle = Handle::create(
            device.into(),
            1500,
            16,
            Callbacks {
                before: count,
                context: Arc::as_ptr(&calls) as usize,
                dns: vec![],
                bootstrap_host: None,
                failures: Arc::new(AtomicU64::new(0)),
            },
        )
        .unwrap();
        let payload = json!({"schemaVersion":2,"node":{"schemaVersion":1,"id":"strict-node","name":"Test","endpoint":{"host":"127.0.0.1","port":18080},"protocol":{"kind":"socks5"},"transport":{"kind":"tcp"},"security":{"kind":"none"},"credentialRef":"secret:test","requirements":[],"sourceRef":null},"credential":{"kind":"username_password","username":"test","password":"test-only"},"configRevision":1,"dns":{"bootstrapServers":["127.0.0.1:5353"],"user":{"route":"selected_proxy","servers":["127.0.0.1:5353"]}}});
        let original=serde_json::to_string(&json!({"schemaVersion":1,"requestId":"strict","idempotencyKey":"strict","expectedRevision":0,"method":"connect","payload":payload})).unwrap();
        for (needle, replacement) in [
            (
                "\"password\":\"test-only\"",
                "\"password\":\"test-only\",\"password\":\"different\"",
            ),
            (
                "\"kind\":\"socks5\"",
                "\"kind\":\"socks5\",\"kind\":\"vless\"",
            ),
            ("\"port\":18080", "\"port\":18080,\"port\":18081"),
            (
                "\"route\":\"selected_proxy\"",
                "\"route\":\"selected_proxy\",\"route\":\"direct\"",
            ),
            (
                "\"bootstrapServers\":[\"127.0.0.1:5353\"]",
                "\"bootstrapServers\":[\"127.0.0.1:5353\"],\"bootstrapServers\":[]",
            ),
            (
                "\"servers\":[\"127.0.0.1:5353\"]",
                "\"servers\":[\"127.0.0.1:5353\"],\"servers\":[]",
            ),
        ] {
            assert!(original.contains(needle));
            let input = original.replace(needle, replacement);
            assert_eq!(handle.request(input.as_bytes()), Err(INVALID_ARGUMENT));
            assert_eq!(handle.shared.snapshot().generation, Revision::ZERO);
            assert_eq!(handle.shared.snapshot().phase, RuntimePhase::Idle);
            assert_eq!(unsafe { libc::fcntl(raw, libc::F_GETFL) }, flags);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
        // Legacy payloads receive a typed migration failure before dispatch,
        // so even a caller bypassing preflight cannot reserve a generation.
        let mut legacy = payload.clone();
        legacy.as_object_mut().unwrap().remove("schemaVersion");
        legacy.as_object_mut().unwrap().remove("dns");
        legacy["dnsServers"] = json!(["127.0.0.1:5353"]);
        let request = serde_json::to_vec(&json!({"schemaVersion":1,"requestId":"legacy","idempotencyKey":"legacy","expectedRevision":0,"method":"connect","payload":legacy})).unwrap();
        let response: Value = serde_json::from_slice(&handle.request(&request).unwrap()).unwrap();
        assert_eq!(response["error"]["code"], "UPGRADE_INCOMPATIBLE");
        assert_eq!(handle.shared.snapshot().generation, Revision::ZERO);
        assert_eq!(handle.shared.snapshot().phase, RuntimePhase::Idle);
        assert_eq!(unsafe { libc::fcntl(raw, libc::F_GETFL) }, flags);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        // Syntactically typed but invalid policies also cannot bypass preflight.
        for (path, field) in [
            ("bootstrapServers", "dns.bootstrapServers"),
            ("user", "dns.user.servers"),
        ] {
            let mut invalid = payload.clone();
            if path == "user" {
                invalid["dns"]["user"]["servers"] = json!([]);
            } else {
                invalid["dns"][path] = json!(["0.0.0.0:53"]);
            }
            let request = serde_json::to_vec(&json!({"schemaVersion":1,"requestId":"invalid-dns","idempotencyKey":"invalid-dns","expectedRevision":0,"method":"connect","payload":invalid})).unwrap();
            let response: Value =
                serde_json::from_slice(&handle.request(&request).unwrap()).unwrap();
            assert_eq!(response["error"]["code"], "CONFIG_INVALID");
            assert_eq!(response["error"]["fieldPath"], field);
            assert_eq!(handle.shared.snapshot().generation, Revision::ZERO);
            assert_eq!(handle.shared.snapshot().phase, RuntimePhase::Idle);
            assert_eq!(unsafe { libc::fcntl(raw, libc::F_GETFL) }, flags);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
        assert_eq!(handle.close(), OK);
    }
}
