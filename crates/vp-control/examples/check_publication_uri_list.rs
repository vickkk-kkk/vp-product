//! TEST HARNESS ONLY: bounded sensitive stdin, actual Rust codec, safe count only.
//! Never installs, fetches, saves, selects, logs or connects any parsed node.
use std::io::Read;
use vp_product_import::{parse, ImportFormat};
use zeroize::Zeroizing;
fn check() -> Result<usize, ()> {
    let mut bytes = Zeroizing::new(Vec::new());
    std::io::stdin()
        .take(262145)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.is_empty() || bytes.len() > 262144 {
        return Err(());
    }
    let batch = parse(&bytes, ImportFormat::UriList).map_err(|_| ())?;
    if !batch.diagnostics.is_empty()
        || batch.has_unimported_fields
        || batch.entries.is_empty()
        || batch.entries.len() > 32
        || batch
            .entries
            .iter()
            .any(|entry| entry.candidate.is_none() || !entry.diagnostics.is_empty())
    {
        return Err(());
    }
    Ok(batch.entries.len())
}
fn main() {
    match check() {
        Ok(count) => println!("{{\"valid\":true,\"entries\":{count}}}"),
        Err(()) => {
            eprintln!("publication codec validation failed");
            std::process::exit(1);
        }
    }
}
