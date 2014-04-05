#include "krx_https.h"

/* --------------------------------------------------------------------------- */
static int krx_https_on_message_begin(http_parser* p);
static int krx_https_on_url(http_parser* p, const char* at, size_t length);
static int krx_https_on_status(http_parser* p, const char* at, size_t length);
static int krx_https_on_header_field(http_parser* p, const char* at, size_t length);
static int krx_https_on_header_value(http_parser* p, const char* at, size_t length);
static int krx_https_on_headers_complete(http_parser* p);
static int krx_https_on_body(http_parser* p, const char* at, size_t length);
static int krx_https_on_message_complete(http_parser* p);

static uv_buf_t krx_https_alloc_buffer(uv_handle_t* handle, size_t nbytes);
static int krx_https_conn_send(krx_https_conn* c, uint8_t* buf, int len);
static void krx_https_conn_on_write(uv_write_t* req, int status); 
static void krx_https_conn_read(uv_stream_t* stream, ssize_t nbytes, uv_buf_t buf);
static int krx_https_conn_init(krx_https* k, krx_https_conn* c);
static void krx_https_on_new_connection(uv_stream_t* server, int status);

static void krx_https_ssl_info_callback(const SSL* ssl, int where, int ret);
static int krx_https_ssl_create(krx_https* k, krx_https_conn* c);
static int krx_https_ssl_verify_peer(int ok, X509_STORE_CTX* ctx);
static int krx_https_ssl_create_ctx(krx_https* k, const char* certfile,  const char* kefile); 
static int krx_https_ssl_check_output_buffer(krx_https_conn* c);
static int krx_https_ssl_check_input_buffer(krx_https_conn* c);

/* --------------------------------------------------------------------------- */

static int krx_https_on_message_begin(http_parser* p) {
  return 0;
}

static int krx_https_on_url(http_parser* p, const char* at, size_t length) {
  return 0;
}

static int krx_https_on_status(http_parser* p, const char* at, size_t length) {
  return 0;
}

static int krx_https_on_header_field(http_parser* p, const char* at, size_t length) {
  return 0;
}

static int krx_https_on_header_value(http_parser* p, const char* at, size_t length) {
  return 0;
}

static int krx_https_on_headers_complete(http_parser* p) {
  return 0;
}

static int krx_https_on_body(http_parser* p, const char* at, size_t length) {

#if 0  
  printf("++++++++++++++++++++++++++++++++\n");
  for(int i = 0; i < length; ++i) {
    printf("%c", at[i]);
  }
  printf("++++++++++++++++++++++++++++++++\n");

  json_error_t err;
  json_t* root = json_loads(at, 0, &err);
  if(!root) {
    printf("Error: krx_https_http_on_body(), failed to parse incoming json.\n");
    return -1;
  }

  json_t* jact = json_object_get(root, "act");
  if(!jact || !json_is_string(jact)) {
    printf("Error: krx_https_http_on_body(), not `act` found in json string.\n");
    json_decref(root);
    return -2;
  }

  const char* act = json_string_value(jact);
  if(strcmp(act, "sdp_offer") == 0) {

    json_t* joffer = json_object_get(root, "offer");
    if(!joffer || !json_is_string(joffer)) {
      printf("Error: krx_https_http_on_body(), no `offer` element found.\n");      
      json_decref(root);
      return -3;
    }

    const char* offer = json_string_value(joffer);
    printf("SDP: %s\n", offer);

  }
  else {
    printf("Error: krx_https_http_on_body(), unhandled act.\n");
    json_decref(root);
    return -4;
  }

  json_decref(root);
#endif

  krx_https_conn* c = (krx_https_conn*)p->data;
  if(!c) {
    printf("Error: no data pointer set on http parser.\n");
    return -5;
  }

  if(c->k && c->k->on_body) {
    c->k->on_body(c, (uint8_t*)at, length);
  }

  return 0;
}

static int krx_https_on_message_complete(http_parser* p) {
  return 0;
}

/* --------------------------------------------------------------------------- */
static uv_buf_t krx_https_alloc_buffer(uv_handle_t* handle, size_t nbytes) {

  char* p = malloc(nbytes);
  if(!p) {
    printf("Error: krx_https_alloc_buffer(), cannot allocate %ld bytes.\n", nbytes);
    exit(1);
  }

  return uv_buf_init(p, nbytes);
}

static void krx_https_conn_on_write(uv_write_t* req, int status) {
  printf("WRITTEN SOME DATA!: status: %d\n", status);
  free(req);
}

static int krx_https_conn_send(krx_https_conn* c, uint8_t* buf, int len) {

  uv_write_t* req = NULL;
  int r = -1;

  printf("Verbose: sending %d bytes.\n", len);

  /* validate input */
  if(!c) {
    printf("Error: krx_https_conn_send, invalid pointer.\n");
    free(buf);
    buf = NULL;
    return -1;
  }

  /* create a write request */
  req = (uv_write_t*)malloc(sizeof(uv_write_t));
  if(!req) {
    printf("Error: krx_https_conn_send(), cannot alloc req.\n");
    free(buf);
    buf = NULL;
    return -2;
  }

  req->data = c;

  uv_buf_t write_buf = uv_buf_init((char*)buf, len);
  r = uv_write(req, (uv_stream_t*)&c->client, &write_buf, 1, krx_https_conn_on_write); 

  if(r != 0) {
    printf("Error: something went wrong with writing the data to connection.\n");
    /* @todo(roxlu): free some things here?? */
    free(write_buf.base);
    buf = NULL;
    return -3;
  }

  /* @todo(roxlu): shouldn't this be free'd in the on_write cb? */
  free(write_buf.base);
  buf = NULL;
  return len;
}

static int krx_https_ssl_check_output_buffer(krx_https_conn* c) {

  if(!c) {
    printf("Error: krx_https_ssl_check_output_buffer(), invalid pointer.\n");
    return -1;
  }

  if(!c->ssl) {
    printf("Error: krx_https_ssl_check_output_buffer(), invalid SSL pointer.\n");
    return -2;
  }

  /* check if there is data in the output bio. */
  int pending = BIO_ctrl_pending(c->out_bio);
  printf("Verbose: pending in out_bio: %d\n", pending);

  if(pending > 0) {

    uint8_t* buffer = (uint8_t*)malloc(pending); /* is free'd after write, @todo(roxlu): make sure it is! */
    if(!buffer) {
      printf("Error: cannot allocate memory for SSL data.\n");
      return -3;
    }

    int nread = BIO_read(c->out_bio, buffer, pending);
    int nsend = krx_https_conn_send(c, buffer, nread);

    if(nsend != nread) {
      printf("Error: krx_https_ssl_check_output_buffer(), didn't sent the complete output buffer: %d <> %d\n", nread, nsend);
      return -4;
    }
  }

  return 0;
}

static int krx_https_ssl_check_input_buffer(krx_https_conn* c) {

  if(!c || !c->ssl) {
    printf("Error: krx_https_ssl_check_input_buffer(), invalid pointers.\n");
    return -1;
  }

  printf("Checking input buffer.\n");
  int pending = BIO_ctrl_pending(c->in_bio);
  if(pending > 0) {
    printf("Pending to read: %d\n", pending);
  }

  uint8_t* buf = malloc(pending);
  if(!buf) {
    printf("Error: krx_https_ssl_check_input_buffer(), cannot allocate temp buffer.\n");
    return -2;
  }

  int r = SSL_read(c->ssl, buf, pending);
  if(r < 0) {
    printf("Error: krx_https_ssl_check_input_buffer(), cannot SSL_read().\n");
    free(buf);
    buf = NULL;
    return -3;
  }

#if 0
  // @todo(roxlu): we should add a smarter buffer loop here.
  if(r != pending) {
    printf("Error: krx_https_ssl_check_input_buffer(), didn't read everything .. @todo(roxlu): handle this. read: %d, pending: %d\n", r, pending);
    exit(1);
  }
#endif

  int nparsed = http_parser_execute(&c->http, &c->http_cfg, (const char*)buf, r);
  
#if 0
  for(int i = 0; i < pending; ++i) {
    printf("%c", buf[i]);
  }
  printf("-\n");
#endif

  return pending;
}


static void krx_https_conn_read(uv_stream_t* stream, ssize_t nbytes, uv_buf_t buf) {

  /* disconnected or other error. */
  if(nbytes < 0) {
    printf("Error: krx_https_conn_read(), error: %zd: %s\n", nbytes, uv_strerror(nbytes));
    printf("@todo(roxlu): krx_https_conn_read(), handle disconnecting client.\n");
    free(buf.base);
    uv_close((uv_handle_t*)stream, NULL);
    return;
  }

  /* digest incoming data */
#if 0  
  for(ssize_t i = 0; i < nbytes; ++i) {
    printf("%c", buf.base[i]);
  }
#endif

  krx_https_conn* c = (krx_https_conn*)stream->data;
  if(!c) {
    printf("Error: krx_https_conn_read(),  user pointer not set.\n");
    exit(1);
  }
  
  int written = BIO_write(c->in_bio, buf.base, nbytes);
  printf("nothing written et? %d\n", written);
  if(written > 0) {
    if(!SSL_is_init_finished(c->ssl)) {
      SSL_do_handshake(c->ssl);
      krx_https_ssl_check_output_buffer(c);
    }
    else {
      printf("HANDSHAKE READY\n");
      krx_https_ssl_check_input_buffer(c);
    }
  }
 
  /*
  int nparsed = http_parser_execute(&c->http, &c->http_cfg, buf.base, nbytes);
  printf("-\n");
  printf("READ: %ld, PARSED: %d\n", nbytes, nparsed);
  */
}


static int krx_https_conn_init(krx_https* k, krx_https_conn* c) {

  if(!c) {
    printf("Error: krx_https_conn_init(), invalid connection pointer.\n");
    return -1;
  }

  if(!k) {
    printf("Error: krx_https_conn_init(), invalid krx_https pointer.\n");
    return -2;
  }

  int r = 0;
  
  r = uv_tcp_init(k->loop, &c->client);
  if(r != 0) {
    printf("Error: krx_https_conn_init(), uv_tcp_init() failed for client.\n");
    return -3;
  }

  r = uv_accept((uv_stream_t*)&k->server, (uv_stream_t*)&c->client);
  if(r != 0) {
    printf("Error: krx_https_conn_innit(), uv_accept() failed.\n");
    printf("@todo(roxlu): when closed we need to cleanup! add callback handler.\n");
    uv_close((uv_handle_t*)&c->client, NULL);
    return -4;
  }

  r = uv_read_start((uv_stream_t*)&c->client, krx_https_alloc_buffer, krx_https_conn_read);
  if(r != 0) {
    printf("Error: krx_https_conn_init(), uv_read_start() failed: %s\n", uv_strerror(r));
    return -5;
  }

  if(c->ssl) {
    printf("Error: krx_https_conn_init(), connection already has an ssl object (?!). @todo(roxlu): fix.\n");
  }

  c->k = k;
  c->ssl = NULL;
  c->client.data = c; /* @todo(roxlu): this could be done initialize only once ... */

  /* init http parser */
  c->http_cfg.on_message_begin      = krx_https_on_message_begin;
  c->http_cfg.on_url                = krx_https_on_url;
  c->http_cfg.on_status             = krx_https_on_status;
  c->http_cfg.on_header_field       = krx_https_on_header_field;
  c->http_cfg.on_header_value       = krx_https_on_header_value;
  c->http_cfg.on_headers_complete   = krx_https_on_headers_complete;
  c->http_cfg.on_body               = krx_https_on_body;
  c->http_cfg.on_message_complete   = krx_https_on_message_complete;

  http_parser_init(&c->http , HTTP_REQUEST);
  c->http.data = c;

  /* init ssl */
  r = krx_https_ssl_create(k, c) < 0;
  if(r < 0) {
    return r;
  }

  return 0;
}

static void krx_https_ssl_info_callback(const SSL* ssl, int where, int ret) {
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

static int krx_https_ssl_create(krx_https* k, krx_https_conn* c) {

  if(!k || !c) {
    printf("Error: krx_https_ssl_create(), invalid pointer(s): k: %p, c: %p\n", k, c);
    return -1;
  }

  if(c->ssl) {
    printf("Error: krx_https_ssl_create(), is seems the connection already has a ssl object.\n");
    return -2;
  }

  if(!k->ctx) {
    printf("Error: krx_https_ssl_create(), seems like the SSL_CTX is invalid.\n");
    return -3;
  }

  /* create SSL* */
  c->ssl = SSL_new(k->ctx);
  if(!c->ssl) {
    printf("Error: krx_https_ssl_create(), cannot create new SSL*.\n");
    return -4;
  }

  /* info callback */
  SSL_set_info_callback(c->ssl, krx_https_ssl_info_callback);

  /* bios */
  c->in_bio = BIO_new(BIO_s_mem());
  if(c->in_bio == NULL) {
    printf("Error: cannot allocate read bio.\n");
    return -2;
  }

  BIO_set_mem_eof_return(c->in_bio, -1); /* see: https://www.openssl.org/docs/crypto/BIO_s_mem.html */

  c->out_bio = BIO_new(BIO_s_mem());
  if(c->out_bio == NULL) {
    printf("Error: cannot allocate write bio.\n");
    return -3;
  }

  BIO_set_mem_eof_return(c->out_bio, -1); /* see: https://www.openssl.org/docs/crypto/BIO_s_mem.html */

  SSL_set_bio(c->ssl, c->in_bio, c->out_bio);

  SSL_set_accept_state(c->ssl);

  //  SSL_do_handshake(c->ssl);  


  return 0;
}

static void krx_https_on_new_connection(uv_stream_t* server, int status) {

  if(status == -1) {
    printf("Error: krx_https_on_new_connection(), received an invalid status: %d\n", status);
    return;
  }

  krx_https* k = (krx_https*)server->data;

  if(!k) {
    printf("Error: krx_https_on_new_connection(), data member not set.\n");
    exit(1);
  }

  if(k->num_connections >= k->allocated_connections) {
    printf("Warning: @todo, krx_https_on_new_connect(), not enough space to handle a new connection: allocated: %d, curr: %d\n", k->allocated_connections, k->num_connections);
    exit(1);
  }

  krx_https_conn* c = &k->connections[k->num_connections];
  
  if(krx_https_conn_init(k, c) < 0) {
    printf("Error: cannot innitialize a new connection.\n");
    exit(1);
  }
  
  k->num_connections++;

  printf("Verbose: Got a new connection, total connections: %d.\n", k->num_connections);
};

static int krx_https_ssl_verify_peer(int ok, X509_STORE_CTX* ctx) {
  return 1;
}

static int krx_https_ssl_create_ctx(krx_https* k, const char* certfile,  const char* kefile) {

  int r = 0;

  if(!k) {
    printf("Error: krx_https_ssl_create_ctx(), invalid pointer.\n");
    return -1;
  }

  /* create a new context using DTLS */
  k->ctx = SSL_CTX_new(TLSv1_1_server_method());
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
  SSL_CTX_set_verify(k->ctx, SSL_VERIFY_PEER, krx_https_ssl_verify_peer);

  /* certificate file; contains also the public key */
  r = SSL_CTX_use_certificate_file(k->ctx, certfile, SSL_FILETYPE_PEM);
  if(r != 1) {
    printf("Error: cannot load certificate file.\n");
    ERR_print_errors_fp(stderr);
    return -3;
  }

  /* load private key */
  r = SSL_CTX_use_PrivateKey_file(k->ctx, kefile, SSL_FILETYPE_PEM);
  if(r != 1) {
    printf("Error: cannot load private key file.\n");
    ERR_print_errors_fp(stderr);
    return -4;
  }
  
  /* check if the private key is valid */
  r = SSL_CTX_check_private_key(k->ctx);
  if(r != 1) {
    printf("Error: checking the private key failed. \n");
    ERR_print_errors_fp(stderr);
    return -5;
  }

  return 0;
}

/* --------------------------------------------------------------------------- */

int krx_https_init(krx_https* k, const char* certfile, const char* keyfile) {

  int r = 0;

  if(!k) {
    printf("Error: krx_https_init(), invalid pointer.\n");
    return -1;
  }

  if(k->state & KRX_HTTPS_STATE_INITIALIZED) {
    printf("Error: rkx_signaling_init(), already initialized.\n");
    return -2;
  }

  k->allocated_connections = 10;
  k->connections = malloc(sizeof(krx_https_conn) * k->allocated_connections);
  if(!k->connections) {
    printf("Error: krx_https_init(), cannot initialize connection array.\n");
    return -3;
  }

  k->on_body = NULL;
  k->loop = NULL;
  k->num_connections = 0;
  k->state = KRX_HTTPS_STATE_INITIALIZED;

  /* initialize SSL */
  SSL_library_init();
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();

  /* create the SSL context */
  r = krx_https_ssl_create_ctx(k, certfile, keyfile);
  if(r < 0) {
    return r;
  }

  return 0;
}

int krx_https_shutdown() {

  printf("@todo(roxlu): cleanup https.\n");

  /* shutdown SSL */
  ERR_remove_state(0);
  ENGINE_cleanup();
  CONF_modules_unload(1);
  ERR_free_strings();
  EVP_cleanup();
  sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
  CRYPTO_cleanup_all_ex_data();

  return 0;
}

int krx_https_start(krx_https* k, const char* ip, int port) {

  int r = 0;

  if(!k) {
    printf("Error: krx_https_start(), invalid pointer.\n");
    return -1;
  }

  if( !(k->state & KRX_HTTPS_STATE_INITIALIZED) ) {
    printf("Error: krx_https_start(), not initialized, call krx_https_init() first.\n");
    return -2;
  }
  
  if(!k->loop) {
    k->loop = uv_default_loop();
  }

  r = uv_tcp_init(k->loop, &k->server);
  if(r != 0) {
    printf("Error: krx_https_start(), cannot initialized tcp: %s.\n", uv_strerror(r));
    return -3;
  }

  struct sockaddr_in saddr = uv_ip4_addr(ip, port);
  r = uv_tcp_bind(&k->server, saddr);
  if(r != 0) {
    printf("Error: krx_https_start(), cannot bind the port: %s.\n", uv_strerror(r));
    return -4;
  }

  r = uv_listen((uv_stream_t*)&k->server, 128, krx_https_on_new_connection);
  if(r != 0) {
    printf("Error: krx_https_start(), cannot start listening: %s.\n", uv_strerror(r));
    return -5;
  }

  printf("Lets start!.\n");

  k->state |= KRX_HTTPS_STATE_ACCEPTING;
  k->server.data = k;

  printf("k->server: %p, k: %p\n", &k->server, &k);
  printf("k->num_connections: %d\n", k->num_connections);
  printf("k->allocated_connections: %d\n", k->allocated_connections);
  printf("k->allocated_connections: %p\n", &k->allocated_connections);
  return 0;
}

void krx_https_update(krx_https* k) {

#if !defined(NDEBUG)

  if(!k) {
    printf("Error: krx_https_update(), invalid pointer.\n");
    exit(1);
  }

  if( !(k->state & KRX_HTTPS_STATE_ACCEPTING) ) {
    printf("Error: krx_https_update(), invalid state.\n");
    exit(1);
  } 

  if(!k->loop) {
    printf("Error: krx_https_update(), no loop set.\n");
    exit(1);
  }

#endif

  uv_run(k->loop, UV_RUN_NOWAIT);
}
