//! The sole unsafe boundary. A C caller must provide valid aligned initialized
//! output structs and readable input allocations for the entire call. Numeric
//! checks cannot make arbitrary dangling/forged pointers safe.
use crate::codec;
use std::{
    collections::BTreeMap,
    ffi::c_void,
    panic::{catch_unwind, AssertUnwindSafe},
    ptr,
    sync::{Mutex, OnceLock},
};
use zeroize::Zeroizing;

const OK: i32 = 0;
const INVALID_ARGUMENT: i32 = 1;
const INVALID_UTF8: i32 = 2;
const TOO_LARGE: i32 = 3;
const QUEUE_FULL: i32 = 7;
const INTERNAL: i32 = 11;
const MAX_ALLOCATIONS: usize = 256;
const MAX_TOTAL_OUTPUT: usize = 32 * 1024 * 1024;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct VpBytes {
    pub data: *const u8,
    pub len: u64,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VpOwnedBytes {
    pub data: *mut u8,
    pub len: u64,
    pub allocation: *mut c_void,
}
impl Default for VpOwnedBytes {
    fn default() -> Self {
        Self {
            data: ptr::null_mut(),
            len: 0,
            allocation: ptr::null_mut(),
        }
    }
}
#[derive(Default)]
struct Allocations {
    next: usize,
    bytes: usize,
    entries: BTreeMap<usize, Zeroizing<Vec<u8>>>,
}
static ALLOCATIONS: OnceLock<Mutex<Allocations>> = OnceLock::new();
fn allocations() -> std::sync::MutexGuard<'static, Allocations> {
    // The map is never structurally invalid on panic; recover only this allocator
    // bookkeeping lock so callers can still release existing secret buffers.
    ALLOCATIONS
        .get_or_init(|| Mutex::new(Allocations::default()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
fn allocate(
    a: &mut Allocations,
    mut bytes: Zeroizing<Vec<u8>>,
) -> std::result::Result<VpOwnedBytes, i32> {
    if bytes.is_empty() {
        return Ok(VpOwnedBytes::default());
    }
    if bytes.len() > codec::MAX_WIRE_BYTES {
        return Err(TOO_LARGE);
    }
    if a.entries.len() >= MAX_ALLOCATIONS || a.bytes.saturating_add(bytes.len()) > MAX_TOTAL_OUTPUT
    {
        return Err(QUEUE_FULL);
    }
    // A token is a monotonically allocated integer encoded as an opaque pointer;
    // it is NEVER dereferenced. No token reuse, including after free (ABA guard).
    let token = a.next.checked_add(1).ok_or(INTERNAL)?;
    let owned = VpOwnedBytes {
        data: bytes.as_mut_ptr(),
        len: bytes.len() as u64,
        allocation: token as *mut c_void,
    };
    a.entries.insert(token, bytes);
    a.bytes += owned.len as usize;
    a.next = token;
    Ok(owned)
}

/// # Safety
/// `out` must be NULL or a live, writable, aligned, initialized `VpOwnedBytes`.
/// A nonempty output is rejected without overwriting its existing ownership.
unsafe fn output_ready(out: *mut VpOwnedBytes) -> std::result::Result<(), i32> {
    if out.is_null() || !out.is_aligned() {
        return Err(INVALID_ARGUMENT);
    }
    // SAFETY: caller contract above, alignment checked. No pointee data is read.
    let value = unsafe { &*out };
    if !value.data.is_null() || value.len != 0 || !value.allocation.is_null() {
        return Err(INVALID_ARGUMENT);
    }
    Ok(())
}
/// # Safety
/// Nonempty `input.data` must be readable for `input.len` bytes and stay live.
unsafe fn borrow<'a>(input: VpBytes) -> std::result::Result<&'a [u8], i32> {
    if input.len > codec::MAX_WIRE_BYTES as u64 || input.len > isize::MAX as u64 {
        return Err(TOO_LARGE);
    }
    if input.len == 0 {
        return if input.data.is_null() {
            Ok(&[])
        } else {
            Err(INVALID_ARGUMENT)
        };
    }
    if input.data.is_null() {
        return Err(INVALID_ARGUMENT);
    }
    // SAFETY: bounded length is representable and caller provides live storage.
    let bytes = unsafe { std::slice::from_raw_parts(input.data, input.len as usize) };
    std::str::from_utf8(bytes).map_err(|_| INVALID_UTF8)?;
    Ok(bytes)
}
/// # Safety
/// Requirements of output_ready and borrow both apply. Input/output allocations
/// must not overlap. Concurrent calls require distinct output structs.
unsafe fn call(
    out: *mut VpOwnedBytes,
    body: impl FnOnce() -> std::result::Result<Zeroizing<Vec<u8>>, i32>,
) -> i32 {
    match catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: propagated caller contract; rejects NULL/misaligned/nonempty.
        unsafe {
            output_ready(out)?;
        }
        // Reserve one worst-case output while serialized under this lock BEFORE
        // parsing can create/consume pending candidates. Capacity failure cannot
        // retain an unreturnable preview token or consume a materialize token.
        // No callbacks/reentrant operations occur in the pure body.
        let mut allocator = allocations();
        if allocator.entries.len() >= MAX_ALLOCATIONS
            || allocator.bytes.saturating_add(codec::MAX_WIRE_BYTES) > MAX_TOTAL_OUTPUT
        {
            return Err(QUEUE_FULL);
        }
        allocator.next.checked_add(1).ok_or(INTERNAL)?;
        let owned = allocate(&mut allocator, body()?)?;
        // SAFETY: validated output remains live and writable until return.
        unsafe {
            ptr::write(out, owned);
        }
        Ok::<(), i32>(())
    })) {
        Ok(Ok(())) => OK,
        Ok(Err(status)) => status,
        Err(_) => INTERNAL,
    }
}

/// # Safety
/// See module-level pointer validity/ownership contract.
#[no_mangle]
pub unsafe extern "C" fn vp_codec_abi_info(out: *mut VpOwnedBytes) -> i32 {
    // SAFETY: forwarded C caller contract.
    unsafe { call(out, || Ok(codec::abi_info())) }
}
/// # Safety
/// See module-level pointer validity/ownership contract.
#[no_mangle]
pub unsafe extern "C" fn vp_codec_parse(input: VpBytes, out: *mut VpOwnedBytes) -> i32 {
    // SAFETY: forwarded C caller contract; input checked before dereference.
    unsafe { call(out, || Ok(codec::parse_request(borrow(input)?))) }
}
/// # Safety
/// See module-level pointer validity/ownership contract.
#[no_mangle]
pub unsafe extern "C" fn vp_codec_validate(input: VpBytes, out: *mut VpOwnedBytes) -> i32 {
    // SAFETY: forwarded C caller contract; input checked before dereference.
    unsafe { call(out, || Ok(codec::validate_request(borrow(input)?))) }
}
/// # Safety
/// See module-level pointer validity/ownership contract. Explicitly secret-bearing.
#[no_mangle]
pub unsafe extern "C" fn vp_codec_export(input: VpBytes, out: *mut VpOwnedBytes) -> i32 {
    // SAFETY: forwarded C caller contract; input checked before dereference.
    unsafe { call(out, || Ok(codec::export_request(borrow(input)?))) }
}
/// # Safety
/// `bytes` must be NULL or a live, aligned, writable initialized owned struct.
/// Only an exact live triple from this library frees an allocation. Empty is a
/// no-op. Unknown/mismatched/cross-domain/stale triples are ignored, unchanged.
/// This detects copied stale ownership but does NOT authorize copying ownership
/// or protect concurrent reads of an allocation during free.
#[no_mangle]
pub unsafe extern "C" fn vp_codec_bytes_free(bytes: *mut VpOwnedBytes) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if bytes.is_null() || !bytes.is_aligned() {
            return;
        }
        // SAFETY: caller contract; pointer checked for NULL and alignment only.
        let owned = unsafe { &mut *bytes };
        if owned.data.is_null() && owned.len == 0 && owned.allocation.is_null() {
            return;
        }
        let token = owned.allocation as usize;
        let mut a = allocations();
        let Some(value) = a.entries.get(&token) else {
            return;
        };
        if value.as_ptr() != owned.data || value.len() as u64 != owned.len {
            return;
        }
        a.bytes -= value.len();
        // Dropping Zeroizing wipes the owned Vec before its own allocator frees.
        a.entries.remove(&token);
        *owned = VpOwnedBytes::default();
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    static TEST: Mutex<()> = Mutex::new(());
    #[test]
    fn unwinding_is_translated_without_partial_output() {
        let _guard = TEST
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut out = VpOwnedBytes::default();
        // SAFETY: live output, injected test-only fixed panic contains no input.
        let status = unsafe { call(&mut out, || panic!("synthetic boundary panic")) };
        assert_eq!(status, INTERNAL);
        assert!(out.data.is_null());
        assert_eq!(out.len, 0);
        assert!(out.allocation.is_null());
    }
    #[test]
    fn output_capacity_failure_precedes_pending_state_mutation() {
        let _guard = TEST
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        allocations().bytes = MAX_TOTAL_OUTPUT;
        let mut out = VpOwnedBytes::default();
        let called = std::cell::Cell::new(false);
        // SAFETY: valid output and no input; test-only closure records entry.
        let status = unsafe {
            call(&mut out, || {
                called.set(true);
                Ok(Zeroizing::new(vec![1]))
            })
        };
        allocations().bytes = 0;
        assert_eq!(status, QUEUE_FULL);
        assert!(!called.get());
        assert!(out.data.is_null());
    }
}
