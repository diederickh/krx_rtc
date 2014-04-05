/*

    openssl req -x509 -newkey rsa:2048 -days 3650 -nodes -keyout client-key.pem -out client-cert.pem
    openssl req -x509 -newkey rsa:2048 -days 3650 -nodes -keyout server-key.pem -out server-cert.pem

 */

#ifndef KRX_HTTP_SERVER_H
#define KRX_HTTP_SERVER_H

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

#define KRX_HTTPS_STATE_NONE 0
#define KRX_HTTPS_STATE_INITIALIZED 1
#define KRX_HTTPS_STATE_ACCEPTING 2

typedef struct krx_https krx_https;
typedef struct krx_https_conn krx_https_conn;
typedef void(*krx_https_on_body_cb)(krx_https_conn* c, uint8_t* buf, int nbytes);

struct krx_https_conn {
  uv_tcp_t client;
  SSL* ssl;
  BIO* in_bio;
  BIO* out_bio;
  http_parser_settings http_cfg;
  http_parser http;
  krx_https* k;
};

struct krx_https {

  /* tcp / TLS */
  uv_tcp_t server;
  uv_loop_t* loop;
  int state;
  SSL_CTX* ctx;

  /* managing connections */
  krx_https_conn* connections;
  int num_connections;
  int allocated_connections;

  /* callback */
  krx_https_on_body_cb on_body;
};

int krx_https_init(krx_https* k, const char* certfile, const char* keyfile);
int krx_https_shutdown(krx_https* k);
int krx_https_start(krx_https* k, const char* ip, int port);
void krx_https_update(krx_https* k);


#endif
