#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "krx_ice.h"

/* STATICS                                                                */
/* ---------------------------------------------------------------------- */
static int create_listening_socket(char* ip, int port, krx_ice_conn** conn);                                               /* creates a listening socket */
static int resolve_stun_server(krx_ice* ice, char* host, char* port);                                                      /* resolves the stun server; when done we will init the stun client */
static int on_must_send_stunc(krx_stunc* stunc, uint8_t* data, int nbytes);                                                /* is called by stunc when we need to send some data */
static void on_stun_server_resolved(uv_getaddrinfo_t* resolver, int status, struct addrinfo* res);                         /* is called when we've resolved the stun server */
static uv_buf_t on_alloc(uv_handle_t* handle, size_t nbytes);                                                              /* allocate a uv_buf_f for the given amount of data */
static void on_stunc_read(uv_udp_t* handle, ssize_t nread, uv_buf_t buf, struct sockaddr* addr, unsigned flags);           /* gets called when we received some info from our remove stun server */
static void on_stunc_send(uv_udp_send_t* req, int status);                                                                 /* gets called when we've send something to the stun server */ 

/* API                                                                    */
/* ---------------------------------------------------------------------- */
krx_ice* krx_ice_alloc() {
  krx_ice* ice = (krx_ice*)malloc(sizeof(krx_ice));
  if(!ice) {
    return NULL;
  }

  ice->sdp = krx_sdp_writer_alloc();
  if(!ice->sdp) {
    goto error;
  }

  ice->stunc = krx_stunc_alloc();
  if(!ice->stunc) {
    goto error;
  }

  ice->mem = krx_mem_alloc(65536, 10);
  if(!ice->mem) {
    goto error;
  }

  ice->mem->user = ice;
  ice->stunc->cb_send = on_must_send_stunc; /* @todo: krx_ice_alloc(), lets rename cb_send and cb_user to send_callback and user. */
  ice->stunc->cb_user = ice;
  ice->connections = NULL;  

  return ice;

 error:
  
  if(ice && ice->sdp) {
    free(ice->sdp);
    ice->sdp = NULL;
  }
  if(ice && ice->stunc) {
    free(ice->stunc);
    ice->stunc = NULL;
  }
  if(ice && ice->mem) {
    free(ice->mem);
    ice->mem = NULL;
  }
  free(ice);

  return NULL;
}

krx_ice_conn* krx_ice_conn_alloc() {
  krx_ice_conn* conn = (krx_ice_conn*)malloc(sizeof(krx_ice_conn));
  if(!conn) {
    return NULL;
  }
  conn->next = NULL;
  return conn;
}

/*
  krx_ice_start:
       we will connect to a stun server and retrieve possible
       candidates that can be used to  for connectivity checks.
       all experimental.... getting to know the ice protocol. 
*/
int krx_ice_start(krx_ice* ice) {

  int r = 0;

  if(!ice) { return -1; } 

  /* resolve the stun server that we use to gather canidates */
  if(resolve_stun_server(ice, "stun.l.google.com", "19302") < 0) {
    return -2;
  };

  return 0;
}

void krx_ice_update(krx_ice* ice) {

  if(!ice) { 
    printf("Error: cannot update. invalid param.\n");
    exit(1);
  }

  uv_run(uv_default_loop(), UV_RUN_ONCE);
}

/* STATICS                                                                */
/* ---------------------------------------------------------------------- */

static int create_listening_socket(char* ip, int port, krx_ice_conn** conn) {
  struct sockaddr_in addr;
  krx_ice_conn* c = NULL;
  int r = -1;

  if(!ip) { return -1; } 

  /* alloc connection + init socket */
  c = krx_ice_conn_alloc();

  if(!c) { return -3; }

  r = uv_udp_init(uv_default_loop(), &c->sock);
  if(r < 0) {
    free(c);
    return r;
  }

  /* bind socket */
  addr = uv_ip4_addr(ip, port);
  r = uv_udp_bind(&c->sock, addr, 0);
  if(r < 0) {
    free(c);
    return r;
  }

  *conn = c;

  return 0;
}

/*
  on_must_send_stunc:
      whenever the stun-client needs to send some data back, this function
      is called. krx_ice uses a stun client to retrieve the public IP:PORT
      that can be used for connectivity checks.
 */


static int on_must_send_stunc(krx_stunc* stunc, uint8_t* data, int nbytes) {

  krx_ice* ice = (krx_ice*)stunc->cb_user;
  if(!ice) {
    printf("Error: the stunc->cb_user is not set.\n");
    return -1;
  }

  uv_udp_send_t* req = (uv_udp_send_t*)malloc(sizeof(uv_udp_send_t));
  if(!req) {
    printf("Error: cannot allocate a send request.\n");
    return -2;
  }

  uv_buf_t* buf = (uv_buf_t*)malloc(sizeof(uv_buf_t));
  if(!buf) {
    return -3;
  }

  /* get a free memory block that we use to send data */
  krx_mem_block* block = krx_mem_get_free(ice->mem);
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

  printf("Sending some data.\n");
  int r = uv_udp_send(req, &ice->server, buf, 1, ice->raddr, on_stunc_send);
  if(r < 0) {
    printf("Error: cannot send.\n");
  }

  return 0;
}


static void on_stunc_read(uv_udp_t* handle, ssize_t nread, uv_buf_t buf, struct sockaddr* addr, unsigned flags) {
  printf("Read something.\n");

  krx_ice* ice = (krx_ice*)handle->data;
  if(!ice) {
    printf("Error: user data not set in on_stunc_read.\n");
    exit(1);
  }

  krx_stunc_handle_traffic(ice->stunc, (uint8_t*)buf.base, nread);

  /* free the used block again */
  krx_mem_block* block = krx_mem_find_block(ice->mem, (uint8_t*)buf.base);
  if(!block) {
    printf("Error: cannot find memory block ... -this should/can't happen-\n");
    exit(1);
  }

  krx_mem_set_free(ice->mem, block);
}

void on_stunc_send(uv_udp_send_t* req, int status) {
  printf("Send some data: %d\n", status);

  if(status < 0) {
    printf("Error: cannot send.\n");
    exit(1);
  }

  /* Free memory block again. */
  krx_mem_block* block = (krx_mem_block*)req->data;
  krx_ice* ice = (krx_ice*)block->mem->user;
  krx_mem_set_free(ice->mem, block);
}

static int resolve_stun_server(krx_ice* ice, char* host, char* port) {

  if(!ice) { return -1; } 
  if(!host) { return -2; } 
  if(!port) { return -3; } 

  int r;
  uv_getaddrinfo_t* resolver = (uv_getaddrinfo_t*) malloc(sizeof(uv_getaddrinfo_t));
  struct addrinfo hints;

  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  hints.ai_flags = 0;
  
  resolver->data = ice;

  r = uv_getaddrinfo(uv_default_loop(), resolver, on_stun_server_resolved, host, port, &hints);
  if(r < 0) {
    return -1;
  }

  return 0;
}

static void on_stun_server_resolved(uv_getaddrinfo_t* resolver, int status, struct addrinfo* res) {

  int r;
  krx_ice* ice = (krx_ice*) resolver->data;

  if(status < 0) {
    printf("Error: something went wrong while resolving the stun server.\n");
    exit(1);
  }

  /* get IP */
  char ip[17] = { 0 } ;
  uv_ip4_name((struct sockaddr_in*)res->ai_addr, ip, 16);
  ip[16] = '\0';
  printf("Stun ip: %s\n", ip);

  /* init UDP sock */
  r = uv_udp_init(uv_default_loop(), &ice->server);
  if(r < 0) {
    printf("Error: cannot initialize the socket.\n");
    exit(1);
  }

  /* bind socket */
  struct sockaddr_in addr = uv_ip4_addr("0.0.0.0", 19302);                          /* @todo on_stun_server_resolved(), get port from somewhere */
  r = uv_udp_bind(&ice->server, (struct sockaddr_in)addr, 0);
  if(r < 0) {
    printf("Error: cannot bind:%s \n", uv_strerror(r));
    exit(1);
  }

  ice->raddr = uv_ip4_addr(ip, 19302);
  ice->server.data = ice;

  r = uv_udp_recv_start(&ice->server, on_alloc, on_stunc_read);
  if(r < 0) {
    printf("Error: cannot start receiving on our stun client port.\n");
    exit(1);
  }

  r = krx_stunc_start(ice->stunc);
  if(r < 0) {
    printf("Erorr: cannot kickoff the stun client.\n");
    exit(1);
  }

  free(resolver);
}

static uv_buf_t on_alloc(uv_handle_t* handle, size_t nbytes) {

  krx_ice* ice = (krx_ice*)handle->data;
  if(!ice) {
    printf("Error: handle's reference isn't an ice one...\n");
    exit(1);
  }

  krx_mem_block* block = krx_mem_get_free(ice->mem);
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
