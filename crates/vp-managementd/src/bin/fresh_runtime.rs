//! Separate explicit full-runtime development profile. Never adopts admin-only roots.
#![forbid(unsafe_code)]
#[cfg(target_os = "linux")]
#[path = "../fresh_runtime.rs"]
mod fresh_runtime;
#[cfg(target_os = "linux")]
#[path = "../fresh_web.rs"]
mod fresh_web;
#[cfg(target_os = "linux")]
#[path = "../probes.rs"]
mod probes;
#[cfg(target_os = "linux")]
#[path = "../secret_generation.rs"]
mod secret_generation;
#[cfg(target_os = "linux")]
#[path = "../secret_manager.rs"]
mod secret_manager;
#[cfg(target_os = "linux")]
#[path = "../web.rs"]
mod web;
fn main() -> std::process::ExitCode {
    #[cfg(target_os = "linux")]
    {
        fresh_runtime::main_entry()
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::process::ExitCode::FAILURE
    }
}
