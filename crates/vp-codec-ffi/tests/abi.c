/* Host harness: synthetic text only. Never pass deliberately dangling data;
 * only NULL/oversized spans which the provider must reject before dereference. */
#include "vp_codec.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
int main(void) {
    vp_owned_bytes out = {0};
    assert(sizeof(vp_status) == 4);
    assert(vp_codec_abi_info(NULL) == VP_INVALID_ARGUMENT);
    assert(vp_codec_abi_info(&out) == VP_OK);
    assert(out.data && out.len && out.allocation);
    vp_owned_bytes original = out;
    assert(vp_codec_abi_info(&out) == VP_INVALID_ARGUMENT);
    assert(out.data == original.data);
    vp_owned_bytes malformed = out;
    malformed.len++;
    vp_codec_bytes_free(&malformed);
    assert(malformed.data == original.data); /* invalid triple not touched */
    vp_codec_bytes_free(&out);
    assert(!out.data && !out.len && !out.allocation);
    vp_codec_bytes_free(&out); /* repeated same zeroed owner */
    vp_codec_bytes_free(&original); /* stale copy never dereferenced */
    vp_codec_bytes_free(NULL);
    assert(vp_codec_parse((vp_bytes){NULL, 1}, &out) == VP_INVALID_ARGUMENT);
    assert(vp_codec_parse((vp_bytes){NULL, UINT64_MAX}, &out) == VP_TOO_LARGE);
    uint8_t invalid_utf8[] = {255};
    assert(vp_codec_parse((vp_bytes){invalid_utf8, 1}, &out) == VP_INVALID_UTF8);
    const char *request = "{\"schemaVersion\":1,\"operation\":\"preview\",\"format\":\"node_uri\",\"input\":\"socks5://127.0.0.1:1080#synthetic\"}";
    assert(vp_codec_parse((vp_bytes){(const uint8_t*)request, strlen(request)}, &out) == VP_OK);
    assert(out.len && out.data);
    vp_codec_bytes_free(&out);
    puts("codec C ABI ownership, null, length, UTF-8 and parse checks passed");
    return 0;
}
