//! Prevent the isolated loopback fixture from entering release-profile builds.
fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_LOCAL_PROBE_TEST");
    println!("cargo:rerun-if-env-changed=PROFILE");
    if std::env::var_os("CARGO_FEATURE_LOCAL_PROBE_TEST").is_some()
        && std::env::var("PROFILE").as_deref() != Ok("debug")
    {
        panic!("local-probe-test is forbidden outside the debug profile");
    }
}
