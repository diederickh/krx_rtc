#ifndef KRX_SIGNALING_H
#define KRX_SIGNALING_H

#include <uv.h>
#include <jansson.h>
#include <http_parser.h>
#include <openssl/err.h>
#include <openssl/dh.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/engine.h>

/* SSL debug */
#define SSL_WHERE_INFO(ssl, w, flag, msg) {              \
    if(w & flag) {                                       \
      printf("----- ");                                  \
      printf("%20.20s", msg);                            \
      printf(" - %30.30s ", SSL_state_string_long(ssl)); \
      printf(" - %5.10s ", SSL_state_string(ssl));       \
      printf("\n");                                      \
    }                                                    \
  } 

#define KRX_SIGNALING_STATE_NONE 0
#define KRX_SIGNALING_STATE_INITIALIZED 1
#define KRX_SIGNALING_STATE_ACCEPTING 2

typedef struct krx_signaling krx_signaling;
typedef struct krx_signaling_conn krx_signaling_conn;

struct krx_signaling_conn {
  uv_tcp_t client;
  SSL* ssl;
  BIO* in_bio;
  BIO* out_bio;
  http_parser_settings http_cfg;
  http_parser http;
};

struct krx_signaling {
  uv_tcp_t server;
  uv_loop_t* loop;
  int state;
  SSL_CTX* ssl_ctx;

  krx_signaling_conn* connections;
  int num_connections;
  int allocated_connections;
};

int krx_signaling_init(krx_signaling* k);
int krx_signaling_start(krx_signaling* k, const char* ip, int port);
void krx_signaling_update(krx_signaling* k);

#endif
