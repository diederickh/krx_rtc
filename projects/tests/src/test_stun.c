#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <uv.h>
#include "krx_stun.h"
#include "krx_sdp.h"
#include "krx_utils.h"
#include "krx_memory.h"

typedef struct app app;

struct app {

  /* stunc */
  krx_stunc* stunc;
  krx_mem* mem;
  
  /* networking */
  uv_loop_t* loop;
  uv_udp_t sock;
  struct sockaddr_in raddr;
  char ip[17];
  uint16_t port;
};

void sighandler(int sn);                                                                                            /* we're handling SIGINT .. to shutdown stuff */
uv_buf_t on_alloc(uv_handle_t* handle, size_t nbytes);                                                              /* is called when we need a buffer to store some bytes into */
//aka 'void (*)(uv_udp_t *, ssize_t, uv_buf_t, struct sockaddr *, unsigned int)')
void on_read(uv_udp_t* handle, ssize_t nread, uv_buf_t buf, struct sockaddr* addr, unsigned flags);                 /* is called when we receive some data */
void on_send(uv_udp_send_t* req, int status);                                                                       /* gets called when we've sent some data */
void on_resolved(uv_getaddrinfo_t* resolver, int status, struct addrinfo* res);                                     /* gets called when a server is resolved. */
int stun_send(krx_stunc* s, uint8_t* data, int nbytes);                            
int stun_create_socket(krx_stunc* c);

app ctx;

int main() {

  int r = 0;

#if 1
  /* generate a basic sdp */
  krx_sdp* sdp = krx_sdp_alloc();
  if(!sdp) { 
    printf("Error: invalid sdp.\n"); 
    exit(1);
  } 

  krx_sdp_media* media = krx_sdp_media_alloc();
  if(!media) {
    printf("Error: invalid media.\n");
    exit(1);
  }

  krx_sdp_add_media(sdp, media);

  char sdp_buf[8192];
  if(krx_read_file("./sdp.txt", sdp_buf, sizeof(sdp_buf)) < 0) {
    exit(1);
  }

  printf("\n--------\n%s\n-----------\n", sdp_buf);

  krx_sdp_parse(sdp, sdp_buf, strlen(sdp_buf) + 1);

  exit(0);
#endif

#if 0
  uint8_t b[10];
  uint8_t* ptr = b;
  krx_write_u8(&ptr, 0x01);
  krx_write_u8(&ptr, 0x02);
  krx_write_u8(&ptr, 0x01);
  krx_write_u8(&ptr, 0x03);
  krx_write_be_u16(&ptr, 0x2233);
  krx_hexdump(b, 10);
  exit(0);
#endif

  printf("\n\nStun Test\n\n");

  signal(SIGINT, sighandler);

  /* allocate some memory that we use to send data*/
  ctx.mem = krx_mem_alloc(65536, 10);
  if(!ctx.mem) {
    printf("Error: Cannot allocate memory buffer.\n");
    exit(1);
  }

  /* create our stun client context */
  ctx.stunc = krx_stunc_alloc();
  if(!ctx.stunc) {
    exit(1);
  }
  ctx.stunc->cb_send = stun_send;
  ctx.stunc->cb_user = (void*)&ctx;

  /* create application context */
  ctx.loop = uv_default_loop();
  ctx.port = 19302;

  /* resolv IP for stun server. */
  struct addrinfo hints;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  hints.ai_flags = 0;
  uv_getaddrinfo_t resolver;
  r = uv_getaddrinfo(ctx.loop, &resolver, on_resolved, "stun.l.google.com", "19302", &hints);

  while(1) {
    uv_run(ctx.loop, UV_RUN_DEFAULT);
  }

  return 0;
}

void sighandler(int s) {
  printf("Got signal.\n");
  krx_mem_dealloc(ctx.mem);
  exit(1);
}

int stun_send(krx_stunc* s, uint8_t* data, int nbytes) {
  
  if(nbytes > 1024) {
    printf("Error; cannot send this many bytes for now.\n");
    return -1;
  }

  uv_udp_send_t* req = (uv_udp_send_t*)malloc(sizeof(uv_udp_send_t));
  if(!req) {
    return -2;
  }

  uv_buf_t* buf = (uv_buf_t*)malloc(sizeof(uv_buf_t));
  if(!buf) {
    return -3;
  }

  /* get a free memory block that we use to send data */
  krx_mem_block* block = krx_mem_get_free(ctx.mem);
  if(!block) {
    printf("Error: no free memory block.\n");
    exit(1);
  }
  if(block->size < nbytes) {
    printf("Error: memory block is too tiny.\n");
    exit(1);
  }
  memcpy(block->buf, data, nbytes);

  buf->base = (char*)block->buf;
  buf->len = nbytes;
  req->data = block;
  
  krx_hexdump(data, nbytes);
  printf("Sending some data.\n");
  int r = uv_udp_send(req, &ctx.sock, buf, 1, ctx.raddr, on_send);
  if(r < 0) {
    printf("Error: cannot send.\n");
  }
  return 0;
}

int stun_create_socket(krx_stunc* c) {

  int r = uv_udp_init(ctx.loop, &ctx.sock);
  if(r < 0) {
    printf("Error: cannot create sock.\n");
    exit(1);
  }

  ctx.raddr = uv_ip4_addr("0.0.0.0", 0);

  return 0;
}

uv_buf_t on_alloc(uv_handle_t* handle, size_t nbytes) {

  krx_mem_block* block = krx_mem_get_free(ctx.mem);
  if(!block) {
    printf("Error: there are no free memory blocks anymore :( \n");
    exit(1);
  }

  if(block->size < nbytes) {
    printf("Error: the memory block we got is smaller then that we need....\n");
    exit(1);
  }

  uv_buf_t buf;
  buf.base = (char*)block->buf;
  buf.len = nbytes;
  return buf;
}

void on_send(uv_udp_send_t* req, int status) {
  printf("Send some data: %d\n", status);

  if(status < 0) {
    printf("Error: cannot send.\n");
    exit(1);
  }

  krx_mem_block* block = (krx_mem_block*)req->data;
  krx_mem_set_free(ctx.mem, block);
}

void on_read(uv_udp_t* handle, ssize_t nread, uv_buf_t buf, struct sockaddr* addr, unsigned flags) {
  printf("Read some data: %ld\n", nread);
  krx_hexdump((uint8_t*)buf.base, nread);
  krx_stunc_handle_traffic(ctx.stunc, (uint8_t*)buf.base, nread);

  /* free the used block again */
  krx_mem_block* block = krx_mem_find_block(ctx.mem, (uint8_t*)buf.base);
  if(!block) {
    printf("Error: cannot find memory block ... -this should/can't happen-\n");
    exit(1);
  }
  krx_mem_set_free(ctx.mem, block);
}

void on_resolved(uv_getaddrinfo_t* resolver, int status, struct addrinfo* res) {

  int r = 0;

  if(status < 0) {
    printf("Something went wrong when resolving the host.\n");
    exit(1);
  }

  /* get IP */
  uv_ip4_name((struct sockaddr_in*)res->ai_addr, ctx.ip, 16);
  ctx.ip[16] = '\0';
  
  
  /* create our sockaddr */
  ctx.raddr = uv_ip4_addr(ctx.ip, ctx.port);
  printf("Resolved host: %s\n", ctx.ip);

  /* init UDP sock */
  r = uv_udp_init(ctx.loop, &ctx.sock);
  if(r < 0) {
    printf("Error: cannot create sock.\n");
    exit(1);
  }

  struct sockaddr_in addr = uv_ip4_addr("0.0.0.0", ctx.port);
  r = uv_udp_bind(&ctx.sock, (struct sockaddr_in)addr, 0);
  if(r < 0) {
    printf("Error: cannot bind: %s\n", uv_strerror(r));
  }

  r = uv_udp_recv_start(&ctx.sock, on_alloc, on_read);
  if(r < 0) {
    printf("Error: cannot start recieving: %s\n", uv_strerror(r));
  }

  /* ready to kickoff stun */
  r = krx_stunc_start(ctx.stunc);
  if(r < 0) {
    printf("Error: cannot start stunc: %d\n", r);
  }
}
