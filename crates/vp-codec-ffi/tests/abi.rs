// Only this test harness module permits unsafe FFI calls with valid storage.
#[allow(unsafe_code, clippy::unwrap_used)]
mod boundary {
    use std::{ptr, sync::Mutex};
    static TEST: Mutex<()> = Mutex::new(());
    use vp_product_codec_ffi::*;
    #[test]
    fn owned_allocation_lifecycle_and_mismatch_validation() {
        let _guard = TEST.lock().unwrap();
        let mut out = VpOwnedBytes::default();
        // SAFETY: live output structs; copied triples never dereference data.
        unsafe {
            assert_eq!(vp_codec_abi_info(&mut out), 0);
            let mut stale = out;
            let mut wrong = out;
            wrong.len += 1;
            vp_codec_bytes_free(&mut wrong);
            assert_eq!(wrong.data, out.data);
            assert_eq!(vp_codec_abi_info(&mut out), 1);
            vp_codec_bytes_free(&mut out);
            assert!(out.data.is_null() && out.allocation.is_null() && out.len == 0);
            vp_codec_bytes_free(&mut out);
            vp_codec_bytes_free(&mut stale);
            vp_codec_bytes_free(ptr::null_mut());
        }
    }
    #[test]
    fn empty_null_huge_utf8_and_error_outputs() {
        let mut out = VpOwnedBytes::default();
        // SAFETY: invalid numeric/null spans must be rejected before dereference.
        unsafe {
            assert_eq!(vp_codec_abi_info(ptr::null_mut()), 1);
            assert_eq!(
                vp_codec_parse(
                    VpBytes {
                        data: ptr::null(),
                        len: 1
                    },
                    &mut out
                ),
                1
            );
            assert_eq!(
                vp_codec_parse(
                    VpBytes {
                        data: ptr::null(),
                        len: u64::MAX
                    },
                    &mut out
                ),
                3
            );
            let invalid = [255u8];
            assert_eq!(
                vp_codec_parse(
                    VpBytes {
                        data: invalid.as_ptr(),
                        len: 1
                    },
                    &mut out
                ),
                2
            );
            assert!(out.data.is_null() && out.len == 0 && out.allocation.is_null());
            assert_eq!(
                vp_codec_parse(
                    VpBytes {
                        data: ptr::null(),
                        len: 0
                    },
                    &mut out
                ),
                0
            );
            let result = std::slice::from_raw_parts(out.data, out.len as usize);
            assert!(std::str::from_utf8(result)
                .unwrap()
                .contains("CONFIG_INVALID"));
            vp_codec_bytes_free(&mut out);
        }
    }
    #[test]
    fn bounded_allocation_registry_recovers_after_release() {
        let _guard = TEST.lock().unwrap();
        let mut outputs = vec![VpOwnedBytes::default(); 256];
        // SAFETY: all owners have distinct live output storage.
        unsafe {
            for out in &mut outputs {
                assert_eq!(vp_codec_abi_info(out), 0);
            }
            let mut overflow = VpOwnedBytes::default();
            assert_eq!(vp_codec_abi_info(&mut overflow), 7);
            assert!(overflow.data.is_null());
            for out in &mut outputs {
                vp_codec_bytes_free(out);
            }
            assert_eq!(vp_codec_abi_info(&mut overflow), 0);
            vp_codec_bytes_free(&mut overflow);
        }
    }
    #[test]
    fn bounded_arbitrary_bytes_never_escape_the_status_boundary() {
        let _guard = TEST.lock().unwrap();
        let mut state = 0x12345678u32;
        for len in 0..256 {
            let mut bytes = vec![0u8; len];
            for byte in &mut bytes {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                *byte = (state >> 16) as u8;
            }
            let mut out = VpOwnedBytes::default();
            // SAFETY: live byte slice and output; zero-length uses required NULL.
            unsafe {
                let input = VpBytes {
                    data: if bytes.is_empty() {
                        ptr::null()
                    } else {
                        bytes.as_ptr()
                    },
                    len: bytes.len() as u64,
                };
                let status = vp_codec_parse(input, &mut out);
                assert!(matches!(status, 0 | 2));
                vp_codec_bytes_free(&mut out);
                assert!(out.data.is_null());
            }
        }
    }
    #[test]
    fn c_layout_is_fixed_width_and_pointer_size_aware() {
        let _guard = TEST.lock().unwrap();
        assert_eq!(std::mem::size_of::<i32>(), 4);
        assert_eq!(std::mem::offset_of!(VpBytes, data), 0);
        assert_eq!(std::mem::offset_of!(VpOwnedBytes, data), 0);
        if cfg!(target_pointer_width = "64") {
            assert_eq!(std::mem::size_of::<VpOwnedBytes>(), 24);
        }
        assert!(std::mem::size_of::<VpOwnedBytes>() >= 2 * std::mem::size_of::<usize>() + 8);
    }
}
