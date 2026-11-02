//! Separate synchronous offline entry point. No HTTP/Tokio/core worker startup.
#![forbid(unsafe_code)]
#[cfg(target_os = "linux")]
#[path = "../maintenance.rs"]
mod maintenance;

fn main() -> std::process::ExitCode {
    #[cfg(target_os = "linux")]
    {
        maintenance::main_entry()
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("offline maintenance requires Linux");
        std::process::ExitCode::FAILURE
    }
}
