#ifndef KRX_GLOBAL_H
#define KRX_GLOBAL_H

#include <pjlib.h>
#include <pjlib-util.h>
#include <pjmedia/sdp.h>
#include <openssl/err.h>
#include <openssl/dh.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/engine.h>

int krx_global_init();
int krx_global_shutdown();

#endif
