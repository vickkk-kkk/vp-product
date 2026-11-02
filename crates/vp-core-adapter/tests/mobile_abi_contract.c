/* Compile/link against the real cdylib; no VPN or network changes. */
#include "vp_adapter.h"
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
static vp_bytes span(const char *s) { vp_bytes b={(const uint8_t *)s,strlen(s)}; return b; }
static vp_status protect(void *unused,const vp_connect_context *context) {(void)unused;(void)context;return VP_PERMISSION_DENIED;}
int main(void) {
 vp_owned_bytes output={0};
 assert(vp_adapter_abi_info(&output)==VP_OK);
 assert(output.data && output.allocation && output.len>0);
 assert(memmem(output.data,(size_t)output.len,"\"abiMinor\":1",12));
 const char *versions="\"connectPayloadVersions\":[2]";
 assert(memmem(output.data,(size_t)output.len,versions,strlen(versions)));
 vp_adapter_bytes_free(&output); vp_adapter_bytes_free(&output);
 assert(!output.data && !output.allocation && output.len==0);
 const char *invalid="{\"credential\":{\"kind\":\"password\",\"value\":\"NEVER_ECHO_THIS\"}}";
 assert(vp_adapter_validate_connect(span(invalid),&output)==VP_OK);
 assert(memmem(output.data,(size_t)output.len,"\"valid\":false",13));
 assert(!memmem(output.data,(size_t)output.len,"NEVER_ECHO_THIS",15));
 vp_adapter_bytes_free(&output);
 int fds[2]; assert(pipe(fds)==0); int duplicate=dup(fds[0]); assert(duplicate>=0);
 vp_host_callbacks callbacks={sizeof(callbacks),0,0,protect,0};
 vp_create_options options={0};options.struct_size=sizeof(options);options.abi_major=99;options.abi_minor=1;options.platform_mode=VP_PLATFORM_ANDROID_TUN;options.available_hooks=VP_HOOK_BEFORE_CONNECT;options.required_hooks=VP_HOOK_BEFORE_CONNECT;options.callbacks=&callbacks;options.event_queue_capacity=16;options.packet_queue_capacity=16;options.android_duplicate_tun_fd=duplicate;options.packet_mtu=1500;
 vp_handle *handle=0;assert(vp_adapter_create(&options,&handle)==VP_ABI_INCOMPATIBLE);assert(!handle);assert(fcntl(duplicate,F_GETFD)==-1);assert(fcntl(fds[0],F_GETFD)>=0);close(fds[0]);close(fds[1]);
 assert(vp_adapter_destroy(0)==VP_OK);
 printf("C ABI ownership, preflight, version and fd-failure contract passed\n");return 0;
}
