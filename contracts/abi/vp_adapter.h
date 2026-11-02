#ifndef VP_PRODUCT_ADAPTER_V1_H
#define VP_PRODUCT_ADAPTER_V1_H

/* Independently authored product ABI; not an upstream vp_core ABI copy.
 * An optional mobile-ffi implementation exports this ABI for Android TUN.
 * Implementation presence is not platform/protocol certification; see
 * docs/architecture/MOBILE_RUNTIME_IMPLEMENTATION.md for exact limits.
 * C99/C++ compatible. All integer fields have fixed width. No Rust layouts.
 */
#include <stdint.h>
#include <stddef.h>

#if defined(_WIN32)
# if defined(VP_ADAPTER_BUILD)
#  define VP_API __declspec(dllexport)
# else
#  define VP_API __declspec(dllimport)
# endif
# define VP_CALL __cdecl
#else
# define VP_API __attribute__((visibility("default")))
# define VP_CALL
#endif
#ifdef __cplusplus
extern "C" {
#endif

#define VP_ABI_MAJOR UINT16_C(1)
#define VP_ABI_MINOR UINT16_C(1)
#define VP_MAX_CONTROL_BYTES UINT64_C(1048576)
#define VP_MAX_PACKET_BYTES UINT32_C(65535)
#define VP_MAX_PACKET_BATCH UINT32_C(256)
#define VP_DESTROY_TIMEOUT_MS UINT32_C(5000)

typedef int32_t vp_status;
#define VP_OK INT32_C(0)
#define VP_INVALID_ARGUMENT INT32_C(1)
#define VP_INVALID_UTF8 INT32_C(2)
#define VP_TOO_LARGE INT32_C(3)
#define VP_ABI_INCOMPATIBLE INT32_C(4)
#define VP_UNSUPPORTED INT32_C(5)
#define VP_HOOK_REQUIRED INT32_C(6)
#define VP_QUEUE_FULL INT32_C(7)
#define VP_TIMEOUT INT32_C(8)
#define VP_CLOSED INT32_C(9)
#define VP_BUSY INT32_C(10)
#define VP_INTERNAL INT32_C(11)
#define VP_PERMISSION_DENIED INT32_C(12)

typedef struct vp_handle vp_handle;
typedef struct vp_bytes { const uint8_t *data; uint64_t len; } vp_bytes;
/* Initialize owned outputs to {NULL,0,NULL}. The provider's private allocation
 * token is opaque, not a host allocator pointer. Only vp_*_free may release it. */
typedef struct vp_owned_bytes { uint8_t *data; uint64_t len; void *allocation; } vp_owned_bytes;

typedef uint32_t vp_platform_mode;
#define VP_PLATFORM_LINUX_SERVICE UINT32_C(1)
#define VP_PLATFORM_ANDROID_TUN UINT32_C(2)
#define VP_PLATFORM_APPLE_PACKET_FLOW UINT32_C(3)
#define VP_PLATFORM_WINDOWS_SERVICE UINT32_C(4)

typedef uint64_t vp_host_hook_flags;
#define VP_HOOK_BEFORE_CONNECT UINT64_C(1)
#define VP_HOOK_NETWORK_SNAPSHOT UINT64_C(2)
#define VP_HOOK_PACKET_DEVICE UINT64_C(4)

typedef uint32_t vp_socket_protocol;
#define VP_SOCKET_TCP UINT32_C(1)
#define VP_SOCKET_UDP UINT32_C(2)
/* Purpose is exhaustive and includes bootstrap/subscription/resolver sockets. */
typedef uint32_t vp_socket_purpose;
#define VP_SOCKET_PROXY UINT32_C(1)
#define VP_SOCKET_DNS UINT32_C(2)
#define VP_SOCKET_BOOTSTRAP UINT32_C(3)
#define VP_SOCKET_SUBSCRIPTION UINT32_C(4)
#define VP_SOCKET_CONNECTIVITY_CHECK UINT32_C(5)

typedef struct vp_connect_context {
    uint32_t struct_size;
    vp_socket_protocol protocol;
    vp_socket_purpose purpose;
    uint32_t reserved;
    /* Native socket: POSIX fd or Windows SOCKET bit pattern. Not transferred. */
    uint64_t socket_handle;
    vp_bytes destination_host_utf8;
    uint16_t destination_port;
    uint16_t reserved16;
    uint32_t reserved32;
} vp_connect_context;

/* Called synchronously before first connect/send. VP_OK alone permits use.
 * Android callback must attach JNI thread, protect the socket, clear/translate
 * exceptions and return failure on denied protection. Adapter closes failed
 * sockets. Callback cannot reenter this handle or block on a UI thread.
 * user_context/callbacks remain valid until successful destroy. No UI callback.
 */
typedef vp_status (VP_CALL *vp_before_connect_fn)(void *user_context, const vp_connect_context *context);
/* Host writes UTF-8 JSON into provider-owned bounded scratch storage. It must
 * set out_len <= capacity and must not retain destination. VP_TOO_LARGE means
 * no partial snapshot is accepted. Network reads never bypass protect. */
typedef vp_status (VP_CALL *vp_network_snapshot_fn)(void *user_context, uint8_t *destination, uint64_t capacity, uint64_t *out_len);
typedef struct vp_host_callbacks {
    uint32_t struct_size;
    uint32_t reserved;
    void *user_context;
    vp_before_connect_fn before_connect;
    vp_network_snapshot_fn network_snapshot;
} vp_host_callbacks;

typedef struct vp_create_options {
    uint32_t struct_size;
    uint16_t abi_major;
    uint16_t abi_minor;
    vp_platform_mode platform_mode;
    uint32_t reserved;
    vp_host_hook_flags available_hooks;
    vp_host_hook_flags required_hooks;
    const vp_host_callbacks *callbacks;
    /* UTF-8 absolute application-owned root, validated by platform host. Not a
     * core/plugin/library path. Empty is valid for purely in-memory operation. */
    vp_bytes storage_root_utf8;
    uint32_t event_queue_capacity; /* 16..4096; overflow emits resync_required */
    uint32_t packet_queue_capacity; /* 1..4096 packets; bounded backpressure */
    /* Android only. -1 elsewhere. See transfer contract below. */
    int64_t android_duplicate_tun_fd;
    uint32_t packet_mtu; /* 576..65535 for packet modes; 0 for server */
    uint32_t reserved_tail;
} vp_create_options;

typedef uint32_t vp_ip_family;
#define VP_IPV4 UINT32_C(4)
#define VP_IPV6 UINT32_C(6)
typedef struct vp_packet { vp_bytes bytes; vp_ip_family family; uint32_t reserved; } vp_packet;
typedef struct vp_packet_batch { uint32_t struct_size; uint32_t count; const vp_packet *packets; } vp_packet_batch;
typedef struct vp_owned_packet_batch {
    uint32_t struct_size;
    uint32_t count;
    const vp_packet *packets;
    void *allocation;
} vp_owned_packet_batch;

/* All struct_size values must cover this v1 layout; reserved fields must be 0.
 * Minor extensions append fields. Unknown required hook bits fail closed.
 * ABI major mismatch fails; higher minor is accepted only if every required
 * hook/field is understood. Nonempty spans require readable/writable pointers;
 * zero-length spans use NULL. Rust catches unwindable panics; OOM/abort is a
 * process failure. Caller must still provide valid pointer lifetimes/alignment.
 * On non-OK results owned outputs remain empty (not partial JSON/packets).
 * Control success/failure uses versioned ResultEnvelope, not global last_error.
 */
VP_API vp_status VP_CALL vp_adapter_abi_info(vp_owned_bytes *out_json);
/* ABI 1.1 pure preflight BEFORE VPN consent, interface creation or FD transfer.
 * Check abi_info.connectPayloadVersions contains 2 before consent. This prerelease
 * runtime accepts inner connect schemaVersion:2, with separate dns.bootstrapServers
 * and dns.user:{route:"selected_proxy",servers:[numeric endpoints]}. Both lists
 * require 1..4 endpoints; no implicit user resolver or direct user-DNS fallback.
 * Legacy dnsServers payloads return UPGRADE_INCOMPATIBLE; outer envelopes remain1.
 * payload_json is the exact connect payload, not a CommandEnvelope. No runtime,
 * socket, DNS, filesystem IO or callback is created/invoked. Result JSON is
 * {schemaVersion:1,valid:true,error:null} or valid:false + canonical ProductError.
 * Invalid UTF-8/oversize spans return their vp_status and leave output empty.
 * Unknown/unsupported fields or credentials produce valid:false with no echoes.
 * This is config validation, not protocol or platform connectivity certification.
 */
VP_API vp_status VP_CALL vp_adapter_validate_connect(vp_bytes payload_json, vp_owned_bytes *out_json);
/* On any attempt with a v1-sized options struct and platform Android, a valid
 * nonnegative duplicate FD is consumed, INCLUDING all create failure paths.
 * Caller retains original ParcelFileDescriptor and never closes the duplicate.
 * Struct too short/NULL: no FD field is read, no transfer occurs. Non-Android
 * modes require -1 and never consume a descriptor. Set *out=NULL on failure.
 */
VP_API vp_status VP_CALL vp_adapter_create(const vp_create_options *options, vp_handle **out);
/* Requests copy borrowed input before returning. Accepted long work returns an
 * operationId promptly. Control work is ordered per handle. Does not mean ready.
 * Maximum request and response length VP_MAX_CONTROL_BYTES; strict UTF-8 JSON.
 */
VP_API vp_status VP_CALL vp_adapter_request(vp_handle *handle, vp_bytes request_json, vp_owned_bytes *out_json);
/* One event reader per handle. Run on a background native pump, never UI thread.
 * timeout_ms=0 polls; max 60000; VP_TIMEOUT gives empty output. Event sequence and
 * generation are mandatory. On resync_required obtain an authoritative snapshot.
 */
VP_API vp_status VP_CALL vp_adapter_next_event(vp_handle *handle, uint32_t timeout_ms, vp_owned_bytes *out_json);
/* Packet input preserves IP boundaries/family, copies the ENTIRE batch or none;
 * on QUEUE_FULL no packets consumed. Host may release input immediately on return.
 * Validate IP header family, each length <= MTU/65535, batch count <=256.
 */
VP_API vp_status VP_CALL vp_adapter_packet_write(vp_handle *handle, const vp_packet_batch *input);
/* One packet reader per handle. Output remains allocated until packets_free;
 * host writes each packet to public packetFlow then frees the whole batch once.
 * timeout=0 polls; max 60000. Stop/cancellation unblocks readers with VP_CLOSED.
 */
VP_API vp_status VP_CALL vp_adapter_packet_read(vp_handle *handle, uint32_t timeout_ms, vp_owned_packet_batch *output);
/* Host first stops issuing calls and joins pumps; destroy cannot race a new call.
 * Implementation marks closing, cancels/joins tasks and closes owned resources.
 * Busy active call returns VP_BUSY; timeout after 5000ms returns VP_TIMEOUT.
 * On BUSY/TIMEOUT handle remains valid but closing, retry destroy only. Only OK
 * invalidates handle. NULL is accepted as already destroyed; dangling pointers,
 * duplicate concurrent destroy and new calls after OK are caller errors.
 */
VP_API vp_status VP_CALL vp_adapter_destroy(vp_handle *handle);
/* NULL/empty valid outputs are no-ops. Both reset fields to zero after release;
 * repeated free of the SAME zeroed struct is safe; copied owning structs are not.
 */
VP_API void VP_CALL vp_adapter_bytes_free(vp_owned_bytes *bytes);
VP_API void VP_CALL vp_adapter_packets_free(vp_owned_packet_batch *packets);

#ifdef __cplusplus
}
#endif
#endif /* VP_PRODUCT_ADAPTER_V1_H */
