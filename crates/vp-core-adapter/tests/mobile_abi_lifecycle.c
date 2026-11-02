/* Real shared-library lifecycle and callback-denial tests, no OS TUN/routes. */
#include "vp_adapter.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
static pthread_mutex_t gate=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed=PTHREAD_COND_INITIALIZER;
static int entered=0,released=0;
static vp_status deny(void *unused,const vp_connect_context *context) {
 (void)unused;assert(context->protocol==VP_SOCKET_TCP);assert(context->purpose==VP_SOCKET_PROXY);
 assert(fcntl((int)context->socket_handle,F_GETFD)>=0);
 pthread_mutex_lock(&gate);entered=1;pthread_cond_broadcast(&changed);
 while(!released)pthread_cond_wait(&changed,&gate);
 pthread_mutex_unlock(&gate);return VP_PERMISSION_DENIED;
}
static vp_bytes span(const char *s){vp_bytes b={(const uint8_t*)s,strlen(s)};return b;}
static vp_create_options options(int fd,vp_host_callbacks *callbacks){vp_create_options o={0};o.struct_size=sizeof(o);o.abi_major=VP_ABI_MAJOR;o.abi_minor=VP_ABI_MINOR;o.platform_mode=VP_PLATFORM_ANDROID_TUN;o.available_hooks=VP_HOOK_BEFORE_CONNECT;o.required_hooks=VP_HOOK_BEFORE_CONNECT;o.callbacks=callbacks;o.event_queue_capacity=16;o.packet_queue_capacity=16;o.android_duplicate_tun_fd=fd;o.packet_mtu=1500;return o;}
static uint16_t checksum(const unsigned char *b,size_t n){uint32_t sum=0;for(size_t i=0;i<n;i+=2)sum+=((uint32_t)b[i]<<8)|b[i+1];sum=(sum&65535)+(sum>>16);sum=(sum&65535)+(sum>>16);return(uint16_t)~sum;}
int main(void){
 vp_host_callbacks cb={sizeof(cb),0,0,deny,0};
 vp_owned_bytes output={0};vp_bytes oversized={0,UINT64_MAX};
 assert(vp_adapter_validate_connect(oversized,&output)==VP_TOO_LARGE);assert(!output.allocation);
 assert(vp_adapter_abi_info(0)==VP_INVALID_ARGUMENT);
 for(int i=0;i<16;i++){int tun[2];assert(socketpair(AF_UNIX,SOCK_DGRAM,0,tun)==0);int duplicate=dup(tun[0]);vp_create_options o=options(duplicate,&cb);vp_handle*h=0;assert(vp_adapter_create(&o,&h)==VP_OK);assert(vp_adapter_destroy(h)==VP_OK);assert(fcntl(duplicate,F_GETFD)==-1);assert(fcntl(tun[0],F_GETFD)>=0);close(tun[0]);close(tun[1]);}
 int listener=socket(AF_INET,SOCK_STREAM,0);assert(listener>=0);struct sockaddr_in peer={0};peer.sin_family=AF_INET;peer.sin_addr.s_addr=htonl(INADDR_LOOPBACK);assert(bind(listener,(struct sockaddr*)&peer,sizeof(peer))==0);assert(listen(listener,1)==0);socklen_t len=sizeof(peer);assert(getsockname(listener,(struct sockaddr*)&peer,&len)==0);assert(fcntl(listener,F_SETFL,O_NONBLOCK)==0);
 int tun[2];assert(socketpair(AF_UNIX,SOCK_DGRAM,0,tun)==0);int duplicate=dup(tun[0]);vp_create_options o=options(duplicate,&cb);vp_handle*handle=0;assert(vp_adapter_create(&o,&handle)==VP_OK);
 char request[1600];int size=snprintf(request,sizeof(request),
 "{\"schemaVersion\":1,\"requestId\":\"c-connect\",\"idempotencyKey\":\"c-connect\",\"expectedRevision\":0,\"method\":\"connect\",\"payload\":{" 
 "\"schemaVersion\":2,\"node\":{\"schemaVersion\":1,\"id\":\"c-node\",\"name\":\"Test\",\"endpoint\":{\"host\":\"127.0.0.1\",\"port\":%u},\"protocol\":{\"kind\":\"socks5\"},\"transport\":{\"kind\":\"tcp\"},\"security\":{\"kind\":\"none\"},\"credentialRef\":\"secret:test\",\"requirements\":[],\"sourceRef\":null},"
 "\"credential\":{\"kind\":\"username_password\",\"username\":\"test\",\"password\":\"test-only\"},\"configRevision\":1,\"dns\":{\"bootstrapServers\":[\"127.0.0.1:5353\"],\"user\":{\"route\":\"selected_proxy\",\"servers\":[\"127.0.0.1:5353\"]}}}}",(unsigned)ntohs(peer.sin_port));assert(size>0&&(size_t)size<sizeof(request));
 assert(vp_adapter_request(handle,span(request),&output)==VP_OK);assert(memmem(output.data,(size_t)output.len,"\"accepted\":true",15));vp_adapter_bytes_free(&output);
 unsigned char packet[32]={0x45,0,0,32,0,0,0,0,64,17,0,0,10,89,0,1,127,0,0,1,0xa7,0xf8,0x1e,0x61,0,12,0,0,'t','e','s','t'};uint16_t sum=checksum(packet,20);packet[10]=(unsigned char)(sum>>8);packet[11]=(unsigned char)sum;assert(send(tun[1],packet,sizeof(packet),0)==(ssize_t)sizeof(packet));
 pthread_mutex_lock(&gate);struct timespec deadline;assert(clock_gettime(CLOCK_REALTIME,&deadline)==0);deadline.tv_sec+=5;while(!entered)assert(pthread_cond_timedwait(&changed,&gate,&deadline)==0);pthread_mutex_unlock(&gate);
 assert(accept(listener,0,0)==-1&&(errno==EAGAIN||errno==EWOULDBLOCK));
 assert(vp_adapter_destroy(handle)==VP_TIMEOUT); /* not freed while callback blocked */
 pthread_mutex_lock(&gate);released=1;pthread_cond_broadcast(&changed);pthread_mutex_unlock(&gate);
 assert(vp_adapter_destroy(handle)==VP_OK);assert(fcntl(duplicate,F_GETFD)==-1);assert(fcntl(tun[0],F_GETFD)>=0);assert(accept(listener,0,0)==-1&&(errno==EAGAIN||errno==EWOULDBLOCK));close(listener);close(tun[0]);close(tun[1]);
 /* Stale handles and copied owning tokens are caller errors, not valid inputs.
  * Same zeroed owned struct repeated free and destroy(NULL) tested separately. */
 puts("C ABI repeated lifecycle, pre-I/O denial and in-flight timeout/retry passed");return 0;
}
