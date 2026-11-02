#ifndef VP_PRODUCT_CODEC_V1_H
#define VP_PRODUCT_CODEC_V1_H
#include "vp_adapter.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Pure parse/export/validation API. No lifecycle, network, filesystem, secrets
 * resolution or system-operation exports. Uses adapter byte allocator convention
 * but its OWN free symbol: never mix allocator domains between dynamic libraries.
 * Explicit plaintext import/export inputs and outputs may contain connection
 * credentials. Host must not log/cache them and must require deliberate export.
 * No administrator credential, server private key or vault master key is accepted.
 */
/* Codec ABI version is independent of the runtime adapter ABI. JSON request,
 * consent, pending-candidate, retry and secret-transfer contract: vp_codec.v1.md.
 * Callers initialize output to {NULL,0,NULL}; nonempty outputs are rejected
 * without overwriting ownership. Exact codec-owned triples only may be freed;
 * wrong-domain/mismatched/stale triples are ignored unchanged. Native free
 * zeroizes provider-owned bytes. Pointer validity is still a caller obligation.
 */
#define VP_CODEC_ABI_MAJOR UINT16_C(1)
#define VP_CODEC_ABI_MINOR UINT16_C(0)
#define VP_CODEC_MAX_INPUT_BYTES UINT64_C(8388608)
VP_API vp_status VP_CALL vp_codec_abi_info(vp_owned_bytes *out_json);
VP_API vp_status VP_CALL vp_codec_parse(vp_bytes request_json, vp_owned_bytes *out_json);
VP_API vp_status VP_CALL vp_codec_validate(vp_bytes request_json, vp_owned_bytes *out_json);
VP_API vp_status VP_CALL vp_codec_export(vp_bytes request_json, vp_owned_bytes *out_json);
VP_API void VP_CALL vp_codec_bytes_free(vp_owned_bytes *bytes);
#ifdef __cplusplus
}
#endif
#endif
