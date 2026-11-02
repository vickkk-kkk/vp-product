//! Dedicated synchronous entry: no Tokio or background threads before cwd bind.
#![forbid(unsafe_code)]
#[cfg(target_os = "linux")]
#[path = "../fresh.rs"]
mod fresh;
fn main() -> std::process::ExitCode {
    #[cfg(target_os = "linux")]
    {
        fresh::main_entry()
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::process::ExitCode::FAILURE
    }
}
