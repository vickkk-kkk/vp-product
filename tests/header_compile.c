/* Compile-only ABI declaration/constant smoke test; no implementation is linked. */
#include "../contracts/abi/vp_adapter.h"
#include "../contracts/abi/vp_codec.h"
#include "../contracts/abi/vp_adapter.h"
#include "../contracts/abi/vp_codec.h"

#if defined(__cplusplus)
static_assert(sizeof(vp_status) == 4, "status must be 32 bits");
static_assert(sizeof(vp_host_hook_flags) == 8, "hook flags must be 64 bits");
#else
typedef char status_is_32_bits[(sizeof(vp_status) == 4) ? 1 : -1];
typedef char hooks_are_64_bits[(sizeof(vp_host_hook_flags) == 8) ? 1 : -1];
#endif

vp_status header_compile_smoke(vp_handle *handle) {
    vp_owned_bytes out = {NULL, 0, NULL};
    vp_status status = vp_adapter_next_event(handle, 0, &out);
    vp_adapter_bytes_free(&out);
    return status;
}
