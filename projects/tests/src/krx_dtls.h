/* 

   krx_dtls
   --------
   Experimental wrapper around openSSL. To use this library make sure you call
   `krx_dtls_init()` at least once before calling any of the other functions. When 
   you shutdown your application make sure to call `krx_dtls_shutdown()`. 

   ````c
   krx_dtls_init();  // at the start of your app.

   krx_dtls_t k;
   if(krx_dtls_create(&k) < 0) {
     return -1;
   }


   if(krx_dtls_destroy(&k)) {
   }

   krx_dtls_shutdown(); // at the end of your app.    
   ````

    Create server/client self-signed certificate/key (self signed, DONT ADD PASSWORD) 

         openssl req -x509 -newkey rsa:2048 -days 3650 -nodes -keyout client-key.pem -out client-cert.pem
         openssl req -x509 -newkey rsa:2048 -days 3650 -nodes -keyout server-key.pem -out server-cert.pem

*/

#ifndef ROXLU_KRX_DTLS_H
#define ROXLU_KRX_DTLS_H

#include <stdio.h>
#include <stdlib.h>
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

typedef struct krx_dtls krx_dtls_t;

typedef int(*krx_dtls_data_callback)(krx_dtls_t* k, uint8_t* buf, int len);

typedef enum {
  KRX_DTLS_TYPE_CLIENT = 0,
  KRX_DTLS_TYPE_SERVER = 1
} krx_dtls_type_t;

typedef enum {
  KRX_DTLS_STATE_NONE = 0x00,
  KRX_DTLS_STATE_HANDSHAKE_DONE = 0x01
} krx_dtls_state_t;

struct krx_dtls {
  SSL_CTX* ctx;                                                       /* main ssl context */
  SSL* ssl;                                                           /* the SSL* which represents a "connection" */
  BIO* in_bio;                                                        /* we use memory read bios */
  BIO* out_bio;                                                       /* we use memory write bios */
  krx_dtls_data_callback send;                                        /* the send callback; is called when you need to send data to the other endpoint */
  krx_dtls_type_t type;                                               /* is this a server or client? */
  void* user;                                                         /* user pointer */
  krx_dtls_state_t state;                                             /* state; simply used to check if the handshake has been done. */
};

/* public API */
int krx_dtls_init();                                                  /* initialize; startup SSL/DTLS */
int krx_dtls_shutdown();                                              /* shutdown; destroy SSL/DTLS */
int krx_dtls_create(krx_dtls_t* k);                                   /* create the krx_dtls_t object. setups up a complete SSL context */
int krx_dtls_destroy(krx_dtls_t* k);                                  /* cleans up everything which has been created by krx_dtls_create(). */
int krx_dtls_handle_traffic(krx_dtls_t* k, uint8_t* data, int len);   /* call this whenever you receive data; data is the encrypted data you received. */
int krx_dtls_is_handshake_done(krx_dtls_t* k);                        /* returns -1 when the handshake has been done, else 1 */

/* used internally */
int krx_dtls_ssl_ctx_create(krx_dtls_t* k);                           /* initializes the SSL_CTX */
int krx_dtls_ssl_create(krx_dtls_t* k);                               /* creates a SSL* object */
void krx_dtls_ssl_info_callback(const SSL* ssl, int where, int ret);  /* prints some debug info */
int krx_dtls_ssl_verify_peer(int ok, X509_STORE_CTX* ctx);            /* we use VERIFY_PEER to get the client certificate */
int krx_dtls_ssl_check_output_buffer(krx_dtls_t* k);

#endif
