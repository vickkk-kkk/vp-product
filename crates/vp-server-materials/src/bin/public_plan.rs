//! Offline experimental plan preview. This does not approve, install, bind,
//! start, or certify a service; no credential values are accepted as arguments.
use std::{io::Read, net::SocketAddr, path::PathBuf};
use vp_product_compiler::server_v2::ServerCompilerV2;
use vp_product_domain::ProductConfig;
use vp_product_server_materials::public_recipe_digest;
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
fn run() -> Result<(), &'static str> {
    let mut args = std::env::args_os().skip(1);
    let mut config: Option<PathBuf> = None;
    let mut targets = Vec::<SocketAddr>::new();
    while let Some(arg) = args.next() {
        if arg == "--config" {
            if config.is_some() { return Err("duplicate config argument"); }
            config = Some(PathBuf::from(args.next().ok_or("missing config path")?));
        } else if arg == "--target" {
            let value = args.next().ok_or("missing numeric target")?;
            let value = value.to_str().ok_or("invalid target")?;
            targets.push(value.parse().map_err(|_| "target must be numeric IP:port")?);
            if targets.len() > 64 { return Err("too many targets"); }
        } else { return Err("unknown argument"); }
    }
    let path = config.ok_or("config is required")?;
    let file = std::fs::File::open(path).map_err(|_| "cannot open config")?;
    if !file.metadata().map_err(|_| "cannot inspect config")?.is_file() { return Err("config must be a regular file"); }
    let mut data = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut data).map_err(|_| "cannot read config")?;
    if data.len() as u64 > MAX_CONFIG_BYTES { return Err("config too large"); }
    let source: ProductConfig = serde_json::from_slice(&data).map_err(|_| "invalid product config")?;
    let release = vp_product_core_adapter::inspect_build().map_err(|_| "build identity invalid")?.build.release;
    let compiler = ServerCompilerV2::for_public_experiment(release.clone(), targets).map_err(|_| "invalid targets or release")?;
    let recipe = compiler.compile(&source, &release).map_err(|_| "configuration is unsupported for the experimental profile")?;
    let digest = public_recipe_digest(&recipe).map_err(|_| "cannot digest recipe")?;
    let output = serde_json::json!({ "schemaVersion": 1, "status": "PREVIEW_NOT_APPROVED_NOT_RUNNING", "artifactDigest": digest, "recipe": recipe });
    serde_json::to_writer(std::io::stdout().lock(), &output).map_err(|_| "cannot write preview")?;
    println!();
    Ok(())
}
fn main() {
    if let Err(message) = run() { eprintln!("vp-public-plan: {message}"); std::process::exit(2); }
}
