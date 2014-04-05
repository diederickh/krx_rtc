/*

  krx_https
  ---------
  
  This implements a basic secure HTTPS server that is used by the 
  signaling server we provide. You can either create a self-signed 
  certificate as illustrated below

  Example:
  --------

  ````c

     #include "krx_https.h"

     // ....

     static void on_body(krx_https_conn* k, uint8_t* buf, int len) {
       // handle body data
     }

      // ....

      krx_https k;
      
      if(krx_https_init(&k, "./server-cert.pem", "./server-key.pem") < 0) {
       exit(0);
      }

      // ONLY AFTER INIT YOU CAN SET A BODY CALLBACK!!
      k.on_body = on_body;
      k.user = some_user_ptr;

      if(krx_https_start(&k, "0.0.0.0", 7777) < 0) {
        exit(0);
      }

      // handle incoming/outgoing data
      while(1) {
         krx_https_update(&k);
      }

      // cleanup
      krx_https_shutdown(&k);

   ````

  Create certificate:
  --------------------

      openssl req -x509 -newkey rsa:2048 -days 3650 -nodes -keyout server-key.pem -out server-cert.pem

      ! Make sure that you accept this certificate in your browser 
      ! by opening the url/port on which you're running this server.

 */

#ifndef KRX_HTTP_SERVER_H
#define KRX_HTTP_SERVER_H

#include <uv.h>
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
  int is_free;
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
  void* user;
};

int krx_https_init(krx_https* k, const char* certfile, const char* keyfile);  /* initializes everything */
int krx_https_start(krx_https* k, const char* ip, int port);                  /* start accepting connections on ip and port */
void krx_https_update(krx_https* k);                                          /* call this regularly, it handles all pending data*/
int krx_https_close_connection(krx_https_conn* c);                            /* cleans up and closes the connection; it can be reused again after this */
int krx_https_send_data(krx_https_conn* c, uint8_t* buf, int len);            /* send application data */
int krx_https_shutdown(krx_https* k);                                         /* shutdown everything; cleans up */

#endif
