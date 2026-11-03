//! Experimental Android entry: a real host binding, not release certification.
#![cfg(target_os = "android")]

use std::net::SocketAddr;
use vp_client_mobile_ui::runtime::{RuntimeError, RuntimeHost, RuntimeObservation};
use vp_product_domain::{NodeId, Revision};
use vp_product_import::{mobile::{encode_ephemeral, observe_snapshot, MobileObservation, MobilePayload}, parse, ImportFormat};
use winit::platform::android::activity::AndroidApp;

struct AndroidHost { app: AndroidApp, prepared: Option<MobilePayload> }
impl AndroidHost {
    fn bridge<T>(&self, f: impl FnOnce(&vp_egui_android_jni::AndroidBridge<'_>) -> T) -> Result<T, RuntimeError> {
        // SAFETY: `self.app` owns the AndroidActivity global reference for the
        // entire duration of this call; the bridge never escapes this scope.
        let bridge = unsafe { vp_egui_android_jni::AndroidBridge::from_android_raw(
            self.app.vm_as_ptr().cast(), self.app.activity_as_ptr().cast()) }
            .map_err(|_| RuntimeError::Unavailable)?;
        Ok(f(&bridge))
    }
    fn payload(&self) -> Result<&str, RuntimeError> {
        self.prepared.as_ref().map(MobilePayload::expose).ok_or(RuntimeError::InvalidInput)
    }
}
impl RuntimeHost for AndroidHost {
    fn available(&mut self) -> bool { self.bridge(|b| b.available().unwrap_or(false)).unwrap_or(false) }
    fn observe(&mut self) -> RuntimeObservation {
        let Ok(Ok(snapshot)) = self.bridge(|b| b.snapshot_json()) else { return RuntimeObservation::Unavailable };
        let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else { return RuntimeObservation::Unavailable };
        let Ok(now_ms) = u64::try_from(now.as_millis()) else { return RuntimeObservation::Unavailable };
        match observe_snapshot(&snapshot, now_ms) {
            MobileObservation::Unavailable => RuntimeObservation::Unavailable,
            MobileObservation::Idle => RuntimeObservation::Idle,
            MobileObservation::Starting => RuntimeObservation::Starting,
            MobileObservation::Verifying => RuntimeObservation::Verifying,
            MobileObservation::ReportedActive => RuntimeObservation::ReportedActive,
            MobileObservation::Stopping => RuntimeObservation::Stopping,
            MobileObservation::Failed => RuntimeObservation::Failed,
            MobileObservation::Stale => RuntimeObservation::Stale,
        }
    }
    fn prepare(&mut self, raw_uri: &str, node_id: &str, bootstrap: &[SocketAddr], user_dns: &[SocketAddr]) -> Result<(), RuntimeError> {
        self.prepared = None;
        let mut batch = parse(raw_uri.as_bytes(), ImportFormat::NodeUri).map_err(|_| RuntimeError::InvalidInput)?;
        if batch.entries.len() != 1 || batch.has_unimported_fields || !batch.diagnostics.is_empty() { return Err(RuntimeError::Unsupported); }
        let item = batch.entries.remove(0);
        if !item.diagnostics.is_empty() { return Err(RuntimeError::Unsupported); }
        let candidate = item.candidate.ok_or(RuntimeError::Unsupported)?;
        let id = NodeId::new(node_id).map_err(|_| RuntimeError::InvalidInput)?;
        let payload = encode_ephemeral(candidate, id, Revision::ZERO, bootstrap, user_dns).map_err(|_| RuntimeError::Unsupported)?;
        let accepted = self.bridge(|b| b.preflight(payload.expose()).unwrap_or(false))?;
        if !accepted { return Err(RuntimeError::Unsupported); }
        self.prepared = Some(payload);
        Ok(())
    }
    fn request_consent(&mut self) -> Result<(), RuntimeError> {
        let payload = self.payload()?;
        if self.bridge(|b| b.request_consent(payload).unwrap_or(false))? { Ok(()) } else { Err(RuntimeError::Failed) }
    }
    fn consent_granted(&mut self) -> bool { self.bridge(|b| b.consent_granted().unwrap_or(false)).unwrap_or(false) }
    fn start(&mut self) -> Result<(), RuntimeError> {
        let payload = self.payload()?;
        if self.bridge(|b| b.start(payload).unwrap_or(false))? { Ok(()) } else { Err(RuntimeError::Failed) }
    }
    fn stop(&mut self) -> Result<(), RuntimeError> {
        if self.bridge(|b| b.stop().unwrap_or(false))? { Ok(()) } else { Err(RuntimeError::Failed) }
    }
    fn clear_prepared(&mut self) { self.prepared = None; }
}

#[no_mangle]
fn android_main(app: AndroidApp) {
    let host = AndroidHost { app: app.clone(), prepared: None };
    let options = eframe::NativeOptions { android_app: Some(app), renderer: eframe::Renderer::Glow,
        persist_window: false, ..Default::default() };
    if let Err(error) = eframe::run_native("VPN Parser", options, Box::new(|cc| {
        let ui = vp_client_mobile_ui::MobileApp::new(cc, "Android", Box::new(|| vp_client_core::parser::NodeMetadata {
            id: uuid::Uuid::new_v4().to_string(), timestamp: chrono::Utc::now(),
        })).with_runtime(Box::new(host));
        Ok(Box::new(ui))
    })) { eprintln!("Unable to start VPN Parser UI: {error}"); }
}
