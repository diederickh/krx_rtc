#ifndef KRX_SIGNALING_H
#define KRX_SIGNALING_H

#include <jansson.h>
#include "krx_https.h"

#define KRX_SIGNALING_STATE_NONE 0
#define KRX_SIGNALING_STATE_INITIALIZED 1
#define KRX_SIGNALING_STATE_ACCEPTING 2

typedef struct krx_sig krx_sig;

struct krx_sig {
  krx_https server;
};

int krx_sig_init(krx_sig* k, const char* certfile, const char* keyfile);
int krx_sig_start(krx_sig* k, const char* ip, int port);
void krx_sig_update(krx_sig* k);

#endif
