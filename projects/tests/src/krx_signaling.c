#include <stdio.h>
#include <stdlib.h>
#include "krx_signaling.h"

void krx_sig_on_body(krx_https_conn* c, uint8_t* buf, int nbytes) {

#if !defined(NDEBUG)
  if(!c || !buf) {
    printf("Error: krx_sig_on_body(), invalid arguments.\n");
    return;
  }
#endif

#if 1
  printf("\n++++++++++++++++++++++++++++++++\n\n");
  for(int i = 0; i < nbytes; ++i) {
    printf("%c", buf[i]);
  }
  printf("\n\n++++++++++++++++++++++++++++++++\n");
#endif

  json_error_t err;
  json_t* root = json_loads((const char*)buf, 0, &err);
  if(!root) {
    printf("Error: krx_https_http_on_body(), failed to parse incoming json.\n");
    return;
  }

  json_t* jact = json_object_get(root, "act");
  if(!jact || !json_is_string(jact)) {
    printf("Error: krx_https_http_on_body(), not `act` found in json string.\n");
    json_decref(root);
    return;
  }

  const char* act = json_string_value(jact);
  if(strcmp(act, "sdp_offer") == 0) {

    json_t* joffer = json_object_get(root, "offer");
    if(!joffer || !json_is_string(joffer)) {
      printf("Error: krx_https_http_on_body(), no `offer` element found.\n");      
      json_decref(root);
      return;
    }

    const char* offer = json_string_value(joffer);
    printf("SDP:\n%s\n", offer);
    printf("\n++++++++++++++++++++++++++++++++\n\n");

  }
  else {
    printf("Error: krx_https_http_on_body(), unhandled act.\n");
    json_decref(root);
    return;
  }

  json_decref(root);

  if(krx_https_close_connection(c) < 0) {
    printf("Error: krx_sig_on_body(), closing connection failed.\n");
  }
}

/* ---------------------------------------------------------------- */

int krx_sig_init(krx_sig* k, const char* certfile, const char* keyfile) {

  if(!k) {
    printf("Error: krx_sig_init(), invalid k pointer.\n");
    return -1;
  }
  if(!certfile) {
    printf("Error: krx_sig_init(), invalid certfile.\n");
    return -2;
  }
  if(!keyfile) {
    printf("Error: krx_sig_init(), invalid keyfile.\n");
    return -3;
  }
  
  int r = 0;

  r = krx_https_init(&k->server, certfile, keyfile);
  if(r < 0) {
    return r;
  }

  k->server.on_body = krx_sig_on_body;
  k->server.user = k;

  return 0;
}

int krx_sig_start(krx_sig* k, const char* ip, int port) {

#if !defined(NDEBUG)
  if(!k) {
    printf("Error: krx_sig_start(), invalid pointer for k: %p\n", k);
    return -1;
  }

  if(!ip) {
    printf("Error: krx_sig_start(), invalid ip.\n");
    return -2;
  }

  if(port <= 0) {
    printf("Error: krx_sig_start, invalid port: %d\n", port);
    return -3;
  }
#endif

  return krx_https_start(&k->server, ip, port);
}

void krx_sig_update(krx_sig* k) {

#if !defined(NDEBUG) 
  if(!k) {
    printf("Error: krx_sig_update(), invalid pointer.\n");
    return;
  }
#endif

  krx_https_update(&k->server);
}
