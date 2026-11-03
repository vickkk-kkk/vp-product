//! Narrow JNI caller for the optional Android egui host.
//! No logging, permission request, or network occurs during construction.
use jni::{jni_sig, jni_str, objects::{Global, JClass, JObject}, sys, JavaVM};
use std::marker::PhantomData;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeError { Unavailable, InvalidInput }
#[derive(Clone, Copy)]
enum Call { Available, Preflight, RequestConsent, ConsentGranted, Start, Stop }

/// Holds a borrowed Android Activity global reference, never deletes it.
pub struct AndroidBridge<'a> {
    vm: JavaVM,
    activity: sys::jobject,
    _activity_lifetime: PhantomData<&'a ()>,
}
impl<'a> AndroidBridge<'a> {
    /// # Safety
    /// `vm` must be the live Android VM, and `activity` must be the unowned
    /// JNI global Activity reference supplied by android-activity. Both must
    /// remain valid for the bridge lifetime; do not extend it beyond AndroidApp.
    pub unsafe fn from_android_raw(vm: *mut sys::JavaVM, activity: sys::jobject) -> Result<Self, BridgeError> {
        if vm.is_null() || activity.is_null() { return Err(BridgeError::Unavailable); }
        Ok(Self { vm: unsafe { JavaVM::from_raw(vm) }, activity, _activity_lifetime: PhantomData })
    }
    pub fn available(&self) -> Result<bool, BridgeError> { self.call(Call::Available, None) }
    pub fn preflight(&self, payload: &str) -> Result<bool, BridgeError> { self.call(Call::Preflight, Some(payload)) }
    pub fn request_consent(&self, payload: &str) -> Result<bool, BridgeError> { self.call(Call::RequestConsent, Some(payload)) }
    pub fn consent_granted(&self) -> Result<bool, BridgeError> { self.call(Call::ConsentGranted, None) }
    pub fn start(&self, payload: &str) -> Result<bool, BridgeError> { self.call(Call::Start, Some(payload)) }
    pub fn stop(&self) -> Result<bool, BridgeError> { self.call(Call::Stop, None) }

    fn call(&self, call: Call, payload: Option<&str>) -> Result<bool, BridgeError> {
        validate_payload(payload)?;
        self.vm.attach_current_thread_for_scope(|env| -> jni::errors::Result<bool> {
            // SAFETY: the constructor's contract guarantees the Activity global
            // remains live. This cast borrows it and does not delete the ref.
            let activity = unsafe { env.as_cast_raw::<Global<JObject>>(&self.activity)? };
            let loader = env.call_method(&activity, jni_str!("getClassLoader"),
                jni_sig!("()Ljava/lang/ClassLoader;"), &[])?.l()?;
            let class_name = env.new_string("org.vp.product.runtime.EguiVpnBridge")?;
            let class = env.call_method(&loader, jni_str!("loadClass"),
                jni_sig!("(Ljava/lang/String;)Ljava/lang/Class;"), &[(&class_name).into()])?.l()?;
            let class = env.cast_local::<JClass>(class)?;
            let result = match call {
                Call::Available => env.call_static_method(&class, jni_str!("available"), jni_sig!("()Z"), &[])?,
                Call::Stop => env.call_static_method(&class, jni_str!("stop"), jni_sig!("()Z"), &[])?,
                Call::ConsentGranted => env.call_static_method(&class, jni_str!("consentGranted"),
                    jni_sig!("(Landroid/content/Context;)Z"), &[(&activity).into()])?,
                Call::Preflight => {
                    let text = env.new_string(payload.unwrap_or_default())?;
                    env.call_static_method(&class, jni_str!("preflight"), jni_sig!("(Ljava/lang/String;)Z"), &[(&text).into()])?
                }
                Call::RequestConsent | Call::Start => {
                    let text = env.new_string(payload.unwrap_or_default())?;
                    let name = if matches!(call, Call::Start) { jni_str!("startWithPayload") } else { jni_str!("requestConsent") };
                    env.call_static_method(&class, name, jni_sig!("(Landroid/content/Context;Ljava/lang/String;)Z"),
                        &[(&activity).into(), (&text).into()])?
                }
            };
            result.z()
        }).map_err(|_| BridgeError::Unavailable)
    }
}

fn validate_payload(payload: Option<&str>) -> Result<(), BridgeError> {
    if payload.is_some_and(|v| v.is_empty() || v.len() > 1_048_576) {
        Err(BridgeError::InvalidInput)
    } else { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn null_activity_or_vm_never_constructs_bridge() {
        assert!(matches!(unsafe { AndroidBridge::from_android_raw(std::ptr::null_mut(), std::ptr::null_mut()) }, Err(BridgeError::Unavailable)));
    }
    #[test] fn invalid_payload_is_rejected_before_jni() {
        assert_eq!(validate_payload(Some("")), Err(BridgeError::InvalidInput));
        assert_eq!(validate_payload(Some(&"x".repeat(1_048_577))), Err(BridgeError::InvalidInput));
        assert_eq!(validate_payload(Some("{}")), Ok(()));
        assert_eq!(validate_payload(None), Ok(()));
    }
}
