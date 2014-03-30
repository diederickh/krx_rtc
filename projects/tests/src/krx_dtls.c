#include "krx_dtls.h"

int krx_dtls_init() {
  SSL_library_init();
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();
  return 0;
}

int krx_dtls_shutdown() {
  ERR_remove_state(0);
  ENGINE_cleanup();
  CONF_modules_unload(1);
  ERR_free_strings();
  EVP_cleanup();
  sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
  CRYPTO_cleanup_all_ex_data();
  return 0;
}

int krx_dtls_create(krx_dtls_t* k) {

  int r = 0;

  r = krx_dtls_ssl_ctx_create(k);
  if(r < 0) {
    return r;
  }
    
  r = krx_dtls_ssl_create(k);
  if(r < 0) {
    return r;
  }
  
  return 0;
}

int krx_dtls_ssl_ctx_create(krx_dtls_t* k) {

  int r = 0;

  /* set default state */
  k->state = KRX_DTLS_STATE_NONE;

  /* create a new context using DTLS */
  k->ctx = SSL_CTX_new(DTLSv1_method());
  if(!k->ctx) {
    printf("Error: cannot create SSL_CTX.\n");
    ERR_print_errors_fp(stderr);
    return -1;
  }

  /* set our supported ciphers */
  r = SSL_CTX_set_cipher_list(k->ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
  if(r != 1) {
    printf("Error: cannot set the cipher list.\n");
    ERR_print_errors_fp(stderr);
    return -2;
  }

  /* the client doesn't have to send it's certificate */
  SSL_CTX_set_verify(k->ctx, SSL_VERIFY_PEER, krx_dtls_ssl_verify_peer);

  /* enable srtp */
  r = SSL_CTX_set_tlsext_use_srtp(k->ctx, "SRTP_AES128_CM_SHA1_80");
  if(r != 0) {
    printf("Error: cannot setup srtp.\n");
    ERR_print_errors_fp(stderr);
    return -3;
  }

  /* certificate file; contains also the public key */
  r = SSL_CTX_use_certificate_file(k->ctx, "./server-cert.pem", SSL_FILETYPE_PEM);
  if(r != 1) {
    printf("Error: cannot load certificate file.\n");
    ERR_print_errors_fp(stderr);
    return -4;
  }

  /* load private key */
  r = SSL_CTX_use_PrivateKey_file(k->ctx, "./server-key.pem", SSL_FILETYPE_PEM);
  if(r != 1) {
    printf("Error: cannot load private key file.\n");
    ERR_print_errors_fp(stderr);
    return -5;
  }
  
  /* check if the private key is valid */
  r = SSL_CTX_check_private_key(k->ctx);
  if(r != 1) {
    printf("Error: checking the private key failed. \n");
    ERR_print_errors_fp(stderr);
    return -6;
  }

  return 0;
}

int krx_dtls_ssl_create(krx_dtls_t* k) {

  /* create SSL* */
  k->ssl = SSL_new(k->ctx);
  if(!k->ssl) {
    printf("Error: cannot create new SSL*.\n");
    return -1;
  }

  /* info callback */
  SSL_set_info_callback(k->ssl, krx_dtls_ssl_info_callback);
  
  /* bios */
  k->in_bio = BIO_new(BIO_s_mem());
  if(k->in_bio == NULL) {
    printf("Error: cannot allocate read bio.\n");
    return -2;
  }

  BIO_set_mem_eof_return(k->in_bio, -1); /* see: https://www.openssl.org/docs/crypto/BIO_s_mem.html */

  k->out_bio = BIO_new(BIO_s_mem());
  if(k->out_bio == NULL) {
    printf("Error: cannot allocate write bio.\n");
    return -3;
  }

  BIO_set_mem_eof_return(k->out_bio, -1); /* see: https://www.openssl.org/docs/crypto/BIO_s_mem.html */

  SSL_set_bio(k->ssl, k->in_bio, k->out_bio);

  /* either use the server or client part of the protocol */
  if(k->type == KRX_DTLS_TYPE_SERVER) {
    SSL_set_accept_state(k->ssl);
  }
  else {
    SSL_set_connect_state(k->ssl);
  }

  return 0;
}


void krx_dtls_ssl_info_callback(const SSL* ssl, int where, int ret) {

  if(ret == 0) {
    printf("-- krx_ssl_info_callback: error occured.\n");
    return;
  }

  SSL_WHERE_INFO(ssl, where, SSL_CB_LOOP, "LOOP");
  SSL_WHERE_INFO(ssl, where, SSL_CB_EXIT, "EXIT");
  SSL_WHERE_INFO(ssl, where, SSL_CB_READ, "READ");
  SSL_WHERE_INFO(ssl, where, SSL_CB_WRITE, "WRITE");
  SSL_WHERE_INFO(ssl, where, SSL_CB_ALERT, "ALERT");
  SSL_WHERE_INFO(ssl, where, SSL_CB_READ_ALERT, "READ ALERT");
  SSL_WHERE_INFO(ssl, where, SSL_CB_WRITE_ALERT, "WRITE ALERT");
  SSL_WHERE_INFO(ssl, where, SSL_CB_ACCEPT_LOOP, "ACCEPT LOOP");
  SSL_WHERE_INFO(ssl, where, SSL_CB_ACCEPT_EXIT, "ACCEPT EXIT");
  SSL_WHERE_INFO(ssl, where, SSL_CB_CONNECT_LOOP, "CONNECT LOOP");
  SSL_WHERE_INFO(ssl, where, SSL_CB_CONNECT_EXIT, "CONNECT EXIT");
  SSL_WHERE_INFO(ssl, where, SSL_CB_HANDSHAKE_START, "HANDSHAKE START");
  SSL_WHERE_INFO(ssl, where, SSL_CB_HANDSHAKE_DONE, "HANDSHAKE DONE");
}

int krx_dtls_ssl_verify_peer(int ok, X509_STORE_CTX* ctx) {
  return 1;
}

int krx_dtls_destroy(krx_dtls_t* k) {

  if(!k) {
    return -1;
  }

  if(k->ctx) { 
    SSL_CTX_free(k->ctx);
    k->ctx = NULL;
  }

  if(k->ssl) {
    SSL_free(k->ssl);
    k->ssl = NULL;
  }

  return 0;
}

int krx_dtls_is_handshake_done(krx_dtls_t* k) {
  return (k->state & KRX_DTLS_STATE_HANDSHAKE_DONE) ? 1 : -1;
}

int krx_dtls_handle_traffic(krx_dtls_t* k, uint8_t* data, int len) {

  if(k->type != KRX_DTLS_TYPE_SERVER) { 
    printf("Warning: only handling server types now.\n");
    return -1;
  }

  int written = BIO_write(k->in_bio, data, len);
  if(written > 0) {
    /* not yet ready with the handshake? */
    if(!(k->state & KRX_DTLS_STATE_HANDSHAKE_DONE) 
       && !SSL_is_init_finished(k->ssl)) 
      {
        SSL_do_handshake(k->ssl);
        return krx_dtls_ssl_check_output_buffer(k);
      }
    else {
      k->state |= KRX_DTLS_STATE_HANDSHAKE_DONE;
    }
  }

  return 0;
}

int krx_dtls_ssl_check_output_buffer(krx_dtls_t* k) {
  
  int pending = BIO_ctrl_pending(k->out_bio);
  if(pending > 0) {
    printf("+ Pending bytes in out buffer: %d\n", pending);

    uint8_t buffer[pending];
    int nread = BIO_read(k->out_bio, buffer, sizeof(buffer));
    int nsend = k->send(k, buffer, nread);

    if(nsend != nread) {
      printf("Error: not yet handling a case where we didn't send everything directly.\n");
      exit(EXIT_FAILURE);
    }

    return nsend;
  }
  return 0;
}
