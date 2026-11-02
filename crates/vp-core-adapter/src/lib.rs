//! Product boundary for the pinned vp_core, never an alternative proxy engine.
//!
//! The default feature set remains fail-closed and source-inspection only.
//! `managed-runtime` owns a verified Linux worker process; `mobile-ffi` owns an
//! in-process Android controller and scoped host-protected packet data plane.
//! Implementation or linking is not protocol/platform release certification.
#![deny(unsafe_code)]

pub mod capabilities;
pub mod identity;
pub mod listener_config;
#[cfg(feature = "managed-runtime")]
pub mod managed;
#[cfg(all(feature = "mobile-ffi", unix))]
pub mod mobile;
pub mod runtime;

pub use capabilities::capabilities;
pub use identity::{inspect_build, BuildInspection};
pub use listener_config::{validate_listeners, validate_listeners_json, ListenerValidation};
pub use runtime::CoreAdapter;
