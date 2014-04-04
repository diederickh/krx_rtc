#include <stdio.h>
#include <stdlib.h>
#include "krx_signaling.h"


/* --------------------------------------------------------------------------- */
static uv_buf_t krx_signaling_alloc_buffer(uv_handle_t* handle, size_t nbytes) {

  char* p = malloc(nbytes);
  if(!p) {
    printf("Error: krx_signaling_alloc_buffer(), cannot allocate %ld bytes.\n", nbytes);
    exit(1);
  }

  return uv_buf_init(p, nbytes);
}

static void krx_signaling_conn_read(uv_stream_t* stream, ssize_t nbytes, uv_buf_t buf) {

  /* disconnected or other error. */
  if(nbytes < 0) {
    printf("Error: krx_signaling_conn_read(), error: %zd: %s\n", nbytes, uv_strerror(nbytes));
    printf("@todo(roxlu): krx_signaling_conn_read(), handle disconnecting client.\n");
    free(buf.base);
    uv_close((uv_handle_t*)stream, NULL);
    return;
  }

  /* digest incoming data */
  for(ssize_t i = 0; i < nbytes; ++i) {
    printf("%c", buf.base[i]);
  }
  printf("-\n");
  printf("READ: %ld\n", nbytes);
}

static int krx_signaling_conn_init(krx_signaling* k, krx_signaling_conn* c) {

  if(!c) {
    printf("Error: krx_signaling_conn_init(), invalid connection pointer.\n");
    return -1;
  }

  if(!k) {
    printf("Error: krx_signaling_conn_init(), invalid krx_signaling pointer.\n");
    return -2;
  }

  int r = 0;
  
  r = uv_tcp_init(k->loop, &c->client);
  if(r != 0) {
    printf("Error: krx_signaling_conn_init(), uv_tcp_init() failed for client.\n");
    return -3;
  }

  r = uv_accept((uv_stream_t*)&k->server, (uv_stream_t*)&c->client);
  if(r != 0) {
    printf("Error: krx_signaling_conn_innit(), uv_accept() failed.\n");
    printf("@todo(roxlu): when closed we need to cleanup! add callback handler.\n");
    uv_close((uv_handle_t*)&c->client, NULL);
    return -4;
  }

  r = uv_read_start((uv_stream_t*)&c->client, krx_signaling_alloc_buffer, krx_signaling_conn_read);
  if(r != 0) {
    printf("Error: krx_signaling_conn_init(), uv_read_start() failed: %s\n", uv_strerror(r));
    return -5;
  }

  return 0;
}

static void krx_signaling_on_new_connection(uv_stream_t* server, int status) {

  if(status == -1) {
    printf("Error: krx_signaling_on_new_connection(), received an invalid status: %d\n", status);
    return;
  }

  krx_signaling* k = (krx_signaling*)server->data;

  if(!k) {
    printf("Error: krx_signaling_on_new_connection(), data member not set.\n");
    exit(1);
  }

  if(k->num_connections >= k->allocated_connections) {
    printf("Warning: @todo, krx_signaling_on_new_connect(), not enough space to handle a new connection: allocated: %d, curr: %d\n", k->allocated_connections, k->num_connections);
    exit(1);
  }

  krx_signaling_conn* c = &k->connections[k->num_connections];

  if(krx_signaling_conn_init(k, c) < 0) {
    printf("Error: cannot innitialize a new connection.\n");
    exit(1);
  }
  
  k->num_connections++;

  printf("Got a new connection, total connections: %d.\n", k->num_connections);

};

/* --------------------------------------------------------------------------- */

int krx_signaling_init(krx_signaling* k) {

  if(!k) {
    printf("Error: krx_signaling_init(), invalid pointer.\n");
    return -1;
  }

  if(k->state & KRX_SIGNALING_STATE_INITIALIZED) {
    printf("Error: rkx_signaling_init(), already initialized.\n");
    return -2;
  }

  k->allocated_connections = 10;
  k->connections = malloc(sizeof(krx_signaling_conn) * k->allocated_connections);
  if(!k->connections) {
    printf("Error: krx_signaling_init(), cannot initialize connection array.\n");
    return -3;
  }

  k->loop = NULL;
  k->num_connections = 0;
  k->state = KRX_SIGNALING_STATE_INITIALIZED;

  return 0;
}

int krx_signaling_start(krx_signaling* k, const char* ip, int port) {

  int r = 0;

  if(!k) {
    printf("Error: krx_signaling_start(), invalid pointer.\n");
    return -1;
  }

  if( !(k->state & KRX_SIGNALING_STATE_INITIALIZED) ) {
    printf("Error: krx_signaling_start(), not initialized, call krx_signaling_init() first.\n");
    return -2;
  }
  
  if(!k->loop) {
    k->loop = uv_default_loop();
  }

  r = uv_tcp_init(k->loop, &k->server);
  if(r != 0) {
    printf("Error: krx_signaling_start(), cannot initialized tcp: %s.\n", uv_strerror(r));
    return -3;
  }

  struct sockaddr_in saddr = uv_ip4_addr(ip, port);
  r = uv_tcp_bind(&k->server, saddr);
  if(r != 0) {
    printf("Error: krx_signaling_start(), cannot bind the port: %s.\n", uv_strerror(r));
    return -4;
  }

  r = uv_listen((uv_stream_t*)&k->server, 128, krx_signaling_on_new_connection);
  if(r != 0) {
    printf("Error: krx_signaling_start(), cannot start listening: %s.\n", uv_strerror(r));
    return -5;
  }

  printf("Lets start!.\n");

  k->state |= KRX_SIGNALING_STATE_ACCEPTING;
  k->server.data = k;

  printf("k->server: %p, k: %p\n", &k->server, &k);
  printf("k->num_connections: %d\n", k->num_connections);
  printf("k->allocated_connections: %d\n", k->allocated_connections);
  printf("k->allocated_connections: %p\n", &k->allocated_connections);
  return 0;
}

void krx_signaling_update(krx_signaling* k) {

#if !defined(NDEBUG)

  if(!k) {
    printf("Error: krx_signaling_update(), invalid pointer.\n");
    exit(1);
  }

  if( !(k->state & KRX_SIGNALING_STATE_ACCEPTING) ) {
    printf("Error: krx_signaling_update(), invalid state.\n");
    exit(1);
  } 

  if(!k->loop) {
    printf("Error: krx_signaling_update(), no loop set.\n");
    exit(1);
  }

#endif

  uv_run(k->loop, UV_RUN_NOWAIT);
}
