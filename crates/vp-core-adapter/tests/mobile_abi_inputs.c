/* Deterministic bounded-input fuzz-like sweep of valid borrowed buffers.
 * Not arbitrary pointer fuzzing; caller's readable lifetime remains valid. */
#include "vp_adapter.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void){
 uint32_t rng=0x51f04e31;unsigned char data[4096];
 for(unsigned test=0;test<2000;test++){
  unsigned size=test%sizeof(data);for(unsigned i=0;i<size;i++){rng=rng*1664525u+1013904223u;data[i]=(unsigned char)(rng>>24);}
  vp_bytes input={size?data:0,size};vp_owned_bytes out={0};vp_status status=vp_adapter_validate_connect(input,&out);
  assert(status==VP_OK||status==VP_INVALID_UTF8||status==VP_INVALID_ARGUMENT);
  if(status==VP_OK){assert(out.data&&out.allocation&&out.len);assert(!memmem(out.data,(size_t)out.len,"\"valid\":true",12));}
  else{assert(!out.data&&!out.allocation&&!out.len);}
  vp_adapter_bytes_free(&out);vp_adapter_bytes_free(&out);assert(!out.data&&!out.allocation&&!out.len);
 }
 unsigned char *max=malloc((size_t)VP_MAX_CONTROL_BYTES);assert(max);memset(max,' ',(size_t)VP_MAX_CONTROL_BYTES);vp_bytes boundary={max,VP_MAX_CONTROL_BYTES};vp_owned_bytes out={0};assert(vp_adapter_validate_connect(boundary,&out)==VP_OK);vp_adapter_bytes_free(&out);free(max);
 vp_bytes too_large={0,VP_MAX_CONTROL_BYTES+1};assert(vp_adapter_validate_connect(too_large,&out)==VP_TOO_LARGE);assert(!out.allocation);
 puts("C ABI 2000 bounded-input cases, size boundary and repeated frees passed");return 0;
}
