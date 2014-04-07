#include <stdio.h>
#include <stdlib.h>

#include <openssl/err.h>
#include <openssl/dh.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/engine.h>

/* 

Create server/client self-signed certificate/key

    openssl req -x509 -newkey rsa:2048 -days 3650 -nodes -keyout client-key.pem -out client-cert.pem
    openssl req -x509 -newkey rsa:2048 -days 3650 -nodes -keyout server-key.pem -out server-cert.pem

*/

typedef struct {
  SSL* ssl;
  SSL_CTX* ctx;
  X509* client_cert;
} krx_ssl;

int krx_ssl_init(krx_ssl* k);

int main() {

  printf("SSL test.\n");
  krx_ssl ks;
  if(krx_ssl_init(&ks) < 0) {
    exit(EXIT_FAILURE);
  }

  return EXIT_SUCCESS;
}

int krx_ssl_init(krx_ssl* k) {

  int r = 0;
  OpenSSL_add_all_algorithms();
  SSL_library_init();
  SSL_load_error_strings();
  
  /* create a new context using DTLS */
  k->ctx = SSL_CTX_new(DTLSv1_method());
  if(!k->ctx) {
    printf("Error: cannot create SSL_CTX.\n");
    ERR_print_errors_fp(stderr);
    return -1;
  }

  /* set our supported ciphers */
  r = SSL_CTX_set_cipher_list(k->ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
  if(r <= 0) {
    printf("Error: cannot set the cipher list.\n");
    ERR_print_errors_fp(stderr);
    return -2;
  }

  /* the client doesn't have to send it's certificate */
  SSL_CTX_set_verify(k->ctx, SSL_VERIFY_NONE, NULL);

  /* enable srtp */
  r = SSL_CTX_set_tlsext_use_srtp(k->ctx, "SRTP_AES128_CM_SHA1_80");
  if(r != 0) {
    printf("Error: cannot setup srtp.\n");
    ERR_print_errors_fp(stderr);
    return -3;
  }

  /* load certificate and key */
  r = SSL_CTX_use_certificate_file(k->ctx, "./server-cert.pem", SSL_FILETYPE_PEM);
  if(r <= 0) {
    printf("Error: cannot load certificate file.\n");
    ERR_print_errors_fp(stderr);
    return -4;
  }

  r = SSL_CTX_use_PrivateKey_file(k->ctx, "./server-key.pem", SSL_FILETYPE_PEM);
  if(r <= 0) {
    printf("Error: cannot load private key file.\n");
    ERR_print_errors_fp(stderr);
    return -5;
  }

  return 0;
}
