#include <jni.h>
#include <dlfcn.h>
#include <unistd.h>
#include <cstring>
#include <mutex>
#include <memory>
#include <string>
#include "vp_adapter.h"

namespace {
JavaVM* vm = nullptr;
struct Api {
    void* library = nullptr;
    decltype(&vp_adapter_abi_info) info = nullptr;
    decltype(&vp_adapter_create) create = nullptr;
    vp_status (VP_CALL *validate_connect)(vp_bytes, vp_owned_bytes*) = nullptr;
    decltype(&vp_adapter_request) request = nullptr;
    decltype(&vp_adapter_next_event) event = nullptr;
    decltype(&vp_adapter_destroy) destroy = nullptr;
    decltype(&vp_adapter_bytes_free) free_bytes = nullptr;
    bool ready = false;
};
Api api;
std::once_flag load_once;
void load() {
    std::call_once(load_once, [] {
        api.library = dlopen("libvp_product_core_adapter.so", RTLD_NOW | RTLD_LOCAL);
        if (!api.library) return;
#define VP_LOAD(field, name) api.field = reinterpret_cast<decltype(api.field)>(dlsym(api.library, name))
        VP_LOAD(info, "vp_adapter_abi_info"); VP_LOAD(create, "vp_adapter_create");
        VP_LOAD(validate_connect, "vp_adapter_validate_connect");
        VP_LOAD(request, "vp_adapter_request"); VP_LOAD(event, "vp_adapter_next_event");
        VP_LOAD(destroy, "vp_adapter_destroy"); VP_LOAD(free_bytes, "vp_adapter_bytes_free");
#undef VP_LOAD
        api.ready = api.info && api.create && api.validate_connect && api.request && api.event && api.destroy && api.free_bytes;
    });
}
void fail(JNIEnv* env, const char* code) {
    jclass cls = env->FindClass("java/lang/IllegalStateException");
    if (cls) env->ThrowNew(cls, code);
}
std::string utf8(JNIEnv* env, jstring input) {
    if (!input) return {};
    jclass cls = env->FindClass("java/lang/String");
    jmethodID method = env->GetMethodID(cls, "getBytes", "(Ljava/lang/String;)[B");
    jstring encoding = env->NewStringUTF("UTF-8");
    auto bytes = static_cast<jbyteArray>(env->CallObjectMethod(input, method, encoding));
    env->DeleteLocalRef(encoding); env->DeleteLocalRef(cls);
    if (!bytes || env->ExceptionCheck()) return {};
    jsize len = env->GetArrayLength(bytes);
    std::string output(static_cast<size_t>(len), '\0');
    env->GetByteArrayRegion(bytes, 0, len, reinterpret_cast<jbyte*>(&output[0]));
    env->DeleteLocalRef(bytes);
    return output;
}
jstring java_string(JNIEnv* env, const vp_owned_bytes& data) {
    if (data.len > VP_MAX_CONTROL_BYTES || (data.len && !data.data)) { fail(env, "ABI_INVALID_RESPONSE"); return nullptr; }
    jbyteArray bytes = env->NewByteArray(static_cast<jsize>(data.len));
    if (!bytes) return nullptr;
    env->SetByteArrayRegion(bytes, 0, static_cast<jsize>(data.len), reinterpret_cast<const jbyte*>(data.data));
    jclass cls = env->FindClass("java/lang/String");
    jmethodID constructor = env->GetMethodID(cls, "<init>", "([BLjava/lang/String;)V");
    jstring encoding = env->NewStringUTF("UTF-8");
    auto result = static_cast<jstring>(env->NewObject(cls, constructor, bytes, encoding));
    env->DeleteLocalRef(encoding); env->DeleteLocalRef(bytes); env->DeleteLocalRef(cls);
    return result;
}
struct Bridge {
    vp_handle* core = nullptr;
    jobject service = nullptr;
    jmethodID protect = nullptr;
    vp_host_callbacks callbacks{};
};
vp_status protect(void* context, const vp_connect_context* socket) {
    if (!context || !socket || socket->struct_size < sizeof(vp_connect_context) || socket->socket_handle > INT32_MAX) return VP_INVALID_ARGUMENT;
    auto* bridge = static_cast<Bridge*>(context);
    JNIEnv* env = nullptr;
    bool attached = false;
    jint state = vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
    if (state == JNI_EDETACHED) {
        if (vm->AttachCurrentThread(&env, nullptr) != JNI_OK) return VP_PERMISSION_DENIED;
        attached = true;
    } else if (state != JNI_OK) return VP_PERMISSION_DENIED;
    jboolean ok = env->CallBooleanMethod(bridge->service, bridge->protect, static_cast<jint>(socket->socket_handle), static_cast<jint>(socket->protocol), static_cast<jint>(socket->purpose));
    if (env->ExceptionCheck()) { env->ExceptionClear(); ok = JNI_FALSE; }
    if (attached) vm->DetachCurrentThread();
    return ok == JNI_TRUE ? VP_OK : VP_PERMISSION_DENIED;
}
Bridge* ptr(jlong handle) { return reinterpret_cast<Bridge*>(static_cast<intptr_t>(handle)); }
}
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* value, void*) { vm = value; return JNI_VERSION_1_6; }
extern "C" JNIEXPORT jboolean JNICALL Java_org_vp_product_runtime_NativeRuntime_nativeAvailable(JNIEnv*, jobject) {
    load(); return api.ready ? JNI_TRUE : JNI_FALSE;
}
extern "C" JNIEXPORT jstring JNICALL Java_org_vp_product_runtime_NativeRuntime_abiInfo(JNIEnv* env, jobject) {
    load(); if (!api.ready) { fail(env, "RUNTIME_UNAVAILABLE"); return nullptr; }
    vp_owned_bytes output{};
    const vp_status status = api.info(&output);
    if (status != VP_OK) { api.free_bytes(&output); fail(env, "ABI_INCOMPATIBLE"); return nullptr; }
    jstring result = java_string(env, output); api.free_bytes(&output); return result;
}
extern "C" JNIEXPORT jstring JNICALL Java_org_vp_product_runtime_NativeRuntime_validateConnect(JNIEnv* env, jobject, jstring payload) {
    try {
        load(); if (!api.ready) { fail(env, "RUNTIME_UNAVAILABLE"); return nullptr; }
        auto input = utf8(env, payload); if (env->ExceptionCheck()) return nullptr;
        if (input.size() > VP_MAX_CONTROL_BYTES) { fail(env, "CONTROL_TOO_LARGE"); return nullptr; }
        vp_owned_bytes output{};
        vp_status status = api.validate_connect({reinterpret_cast<const uint8_t*>(input.data()), input.size()}, &output);
        if (status != VP_OK) { api.free_bytes(&output); fail(env, "CONFIG_VALIDATION_FAILED"); return nullptr; }
        jstring result = java_string(env, output); api.free_bytes(&output); return result;
    } catch (...) { fail(env, "NATIVE_INTERNAL"); return nullptr; }
}
extern "C" JNIEXPORT jlong JNICALL Java_org_vp_product_runtime_NativeRuntime_create(JNIEnv* env, jobject, jobject service, jint duplicate_fd, jint mtu, jstring root) {
    // FD ownership crosses at JNI invocation, before any allocation or dynamic load.
    struct Fd { int value; ~Fd() { if (value >= 0) close(value); } } fd{duplicate_fd};
    jobject pending_global = nullptr;
    try {
        load(); if (!api.ready) { fail(env, "RUNTIME_UNAVAILABLE"); return 0; }
        if (fd.value < 0 || !service) { fail(env, "INVALID_ARGUMENT"); return 0; }
        auto bridge = std::make_unique<Bridge>();
        bridge->service = env->NewGlobalRef(service);
        pending_global = bridge->service;
        jclass cls = env->GetObjectClass(service);
        bridge->protect = env->GetMethodID(cls, "protectSocket", "(III)Z");
        env->DeleteLocalRef(cls);
        if (!bridge->service || !bridge->protect || env->ExceptionCheck()) {
            if (bridge->service) env->DeleteGlobalRef(bridge->service);
            pending_global = nullptr;
            return 0;
        }
        auto storage = utf8(env, root);
        if (env->ExceptionCheck()) { env->DeleteGlobalRef(bridge->service); pending_global = nullptr; return 0; }
        bridge->callbacks.struct_size = sizeof(vp_host_callbacks);
        bridge->callbacks.user_context = bridge.get(); bridge->callbacks.before_connect = protect;
        vp_create_options options{};
        options.struct_size = sizeof(options); options.abi_major = VP_ABI_MAJOR; options.abi_minor = VP_ABI_MINOR;
        options.platform_mode = VP_PLATFORM_ANDROID_TUN;
        options.available_hooks = VP_HOOK_BEFORE_CONNECT; options.required_hooks = VP_HOOK_BEFORE_CONNECT;
        options.callbacks = &bridge->callbacks;
        options.storage_root_utf8 = {reinterpret_cast<const uint8_t*>(storage.data()), storage.size()};
        options.event_queue_capacity = 128; options.packet_queue_capacity = 128;
        options.android_duplicate_tun_fd = fd.value; options.packet_mtu = static_cast<uint32_t>(mtu);
        fd.value = -1; // V1-sized options: core consumes duplicate INCLUDING every create failure.
        vp_status status = api.create(&options, &bridge->core);
        if (status != VP_OK || !bridge->core) {
            env->DeleteGlobalRef(bridge->service); pending_global = nullptr; fail(env, "RUNTIME_CREATE_FAILED"); return 0;
        }
        pending_global = nullptr; // Strong reference now belongs to the successfully created Bridge.
        return static_cast<jlong>(reinterpret_cast<intptr_t>(bridge.release()));
    } catch (...) { if (pending_global) env->DeleteGlobalRef(pending_global); fail(env, "NATIVE_INTERNAL"); return 0; }
}
extern "C" JNIEXPORT jstring JNICALL Java_org_vp_product_runtime_NativeRuntime_request(JNIEnv* env, jobject, jlong handle, jstring request) {
    try {
        Bridge* bridge = ptr(handle);
        if (!bridge || !bridge->core) { fail(env, "RUNTIME_CLOSED"); return nullptr; }
        auto input = utf8(env, request); if (env->ExceptionCheck()) return nullptr;
        if (input.size() > VP_MAX_CONTROL_BYTES) { fail(env, "CONTROL_TOO_LARGE"); return nullptr; }
        vp_owned_bytes output{};
        vp_status status = api.request(bridge->core, {reinterpret_cast<const uint8_t*>(input.data()), input.size()}, &output);
        if (status != VP_OK) { api.free_bytes(&output); fail(env, "RUNTIME_REQUEST_FAILED"); return nullptr; }
        jstring result = java_string(env, output); api.free_bytes(&output); return result;
    } catch (...) { fail(env, "NATIVE_INTERNAL"); return nullptr; }
}
extern "C" JNIEXPORT jstring JNICALL Java_org_vp_product_runtime_NativeRuntime_nextEvent(JNIEnv* env, jobject, jlong handle, jint timeout) {
    Bridge* bridge = ptr(handle);
    if (!bridge || !bridge->core || timeout < 0 || timeout > 60000) { fail(env, "INVALID_ARGUMENT"); return nullptr; }
    vp_owned_bytes output{};
    vp_status status = api.event(bridge->core, static_cast<uint32_t>(timeout), &output);
    if (status == VP_TIMEOUT) { api.free_bytes(&output); return nullptr; }
    if (status != VP_OK) { api.free_bytes(&output); fail(env, "RUNTIME_EVENT_FAILED"); return nullptr; }
    jstring result = java_string(env, output); api.free_bytes(&output); return result;
}
extern "C" JNIEXPORT jint JNICALL Java_org_vp_product_runtime_NativeRuntime_destroy(JNIEnv* env, jobject, jlong handle) {
    Bridge* bridge = ptr(handle); if (!bridge) return VP_OK;
    vp_status status = api.destroy(bridge->core);
    if (status == VP_OK) { env->DeleteGlobalRef(bridge->service); delete bridge; }
    return status;
}
