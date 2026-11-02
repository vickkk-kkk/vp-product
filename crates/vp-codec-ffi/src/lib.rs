//! Pure native import codec. No runtime, filesystem, network, or vault access.
#![deny(unsafe_code)]

mod codec;
#[allow(unsafe_code)]
mod ffi;

pub use ffi::{
    vp_codec_abi_info, vp_codec_bytes_free, vp_codec_export, vp_codec_parse, vp_codec_validate,
    VpBytes, VpOwnedBytes,
};
