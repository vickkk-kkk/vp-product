//! Optional immutable same-origin Flutter asset serving. Not a file manager.
use axum::{
    body::Body,
    extract::Request,
    http::{header, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
};
use std::{
    io::Read,
    path::{Component, PathBuf},
    sync::Arc,
};

pub struct WebRoot {
    root: PathBuf,
    host: String,
}
impl WebRoot {
    pub fn open(path: PathBuf, origin: &str) -> Result<Arc<Self>, &'static str> {
        let root = path.canonicalize().map_err(|_| "Web assets unavailable")?;
        if !root.join("index.html").is_file() {
            return Err("Web assets missing index.html");
        }
        let uri: axum::http::Uri = origin.parse().map_err(|_| "invalid Web origin")?;
        let host = uri.authority().ok_or("invalid Web origin")?.to_string();
        Ok(Arc::new(Self { root, host }))
    }
}
pub async fn serve(root: Arc<WebRoot>, request: Request) -> Response {
    if request.method() != Method::GET && request.method() != Method::HEAD {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let mut hosts = request.headers().get_all(header::HOST).iter();
    if hosts.next().and_then(|v| v.to_str().ok()) != Some(root.host.as_str())
        || hosts.next().is_some()
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let path = request.uri().path().to_owned();
    if path == "/api"
        || path.starts_with("/api/")
        || path.contains('%')
        || path.contains('\\')
        || path.split('/').any(|s| s.starts_with('.') && !s.is_empty())
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    let head = request.method() == Method::HEAD;
    let result = tokio::task::spawn_blocking(move || read_asset(&root, &path)).await;
    let Ok(Some((bytes, content_type))) = result else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let representation_length = bytes.len();
    let mut response = if head {
        Body::empty().into_response()
    } else {
        Body::from(bytes).into_response()
    };
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from(representation_length),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
        .headers_mut()
        .insert("x-frame-options", HeaderValue::from_static("DENY"));
    response
        .headers_mut()
        .insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    // Flutter's JS/Wasm bootstrap requires a separately verified CSP profile.
    // API responses remain default-src none; never reuse that policy for app assets.
    response
}
fn read_asset(root: &WebRoot, path: &str) -> Option<(Vec<u8>, &'static str)> {
    let relative = PathBuf::from(path.trim_start_matches('/'));
    if relative
        .components()
        .any(|c| !matches!(c, Component::Normal(_)))
        && !relative.as_os_str().is_empty()
    {
        return None;
    }
    let candidate = if relative.as_os_str().is_empty() {
        root.root.join("index.html")
    } else {
        root.root.join(&relative)
    };
    let candidate = if candidate.is_file() {
        candidate
    } else if relative.extension().is_none() {
        root.root.join("index.html")
    } else {
        return None;
    };
    let canonical = candidate.canonicalize().ok()?;
    if !canonical.starts_with(&root.root) || !canonical.is_file() {
        return None;
    }
    let extension = canonical.extension().and_then(|v| v.to_str()).unwrap_or("");
    let content_type = match extension {
        "html" => "text/html; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json",
        "wasm" => "application/wasm",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "svg" => "image/svg+xml",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "bin" | "frag" => "application/octet-stream",
        "txt" | "symbols" => "text/plain; charset=utf-8",
        "" if canonical.strip_prefix(&root.root).ok()?
            == std::path::Path::new("assets/NOTICES") =>
        {
            "text/plain; charset=utf-8"
        }
        _ => return None,
    };
    let metadata = canonical.metadata().ok()?;
    if metadata.len() > 32 * 1024 * 1024 {
        return None;
    }
    let mut bytes = Vec::new();
    std::fs::File::open(canonical)
        .ok()?
        .take(32 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > 32 * 1024 * 1024 {
        return None;
    }
    Some((bytes, content_type))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn flutter_notice_license_shader_and_symbols_have_safe_mime_types() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("assets")).unwrap();
        for name in [
            "index.html",
            "assets/NOTICES",
            "assets/OFL.txt",
            "assets/shader.frag",
            "bundle.js.symbols",
            "private.unknown",
            ".last_build_id",
        ] {
            std::fs::write(root.path().join(name), b"synthetic public asset").unwrap();
        }
        let web = WebRoot::open(root.path().to_path_buf(), "http://127.0.0.1:18080").unwrap();
        for (name, mime) in [
            ("assets/NOTICES", "text/plain; charset=utf-8"),
            ("assets/OFL.txt", "text/plain; charset=utf-8"),
            ("assets/shader.frag", "application/octet-stream"),
            ("bundle.js.symbols", "text/plain; charset=utf-8"),
        ] {
            let (bytes, actual) = read_asset(&web, &format!("/{name}")).unwrap();
            assert_eq!(bytes, b"synthetic public asset");
            assert_eq!(actual, mime);
        }
        assert!(read_asset(&web, "/private.unknown").is_none());
        assert!(read_asset(&web, "/../index.html").is_none());
    }
    #[tokio::test]
    async fn head_preserves_get_length_and_reserved_api_never_serves_spa() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("index.html"), b"synthetic public page").unwrap();
        let web = WebRoot::open(root.path().to_path_buf(), "http://127.0.0.1:18080").unwrap();
        for method in [Method::GET, Method::HEAD] {
            let request = Request::builder()
                .method(method.clone())
                .uri("/")
                .header(header::HOST, "127.0.0.1:18080")
                .body(Body::empty())
                .unwrap();
            let response = serve(web.clone(), request).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers()[header::CONTENT_LENGTH],
                b"synthetic public page".len().to_string()
            );
            assert!(response.headers().get("content-security-policy").is_none());
            assert_eq!(response.headers()["x-content-type-options"], "nosniff");
            let body = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            assert_eq!(
                body.as_ref(),
                if method == Method::HEAD {
                    b"".as_slice()
                } else {
                    b"synthetic public page".as_slice()
                }
            );
        }
        for path in [
            "/api",
            "/api/unknown",
            "/.last_build_id",
            "/%2e%2e/index.html",
        ] {
            let request = Request::builder()
                .uri(path)
                .header(header::HOST, "127.0.0.1:18080")
                .body(Body::empty())
                .unwrap();
            assert_eq!(
                serve(web.clone(), request).await.status(),
                StatusCode::NOT_FOUND
            );
        }
    }
}
