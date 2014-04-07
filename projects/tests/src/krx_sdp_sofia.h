#ifndef KRX_SDP_H
#define KRX_SDP_H

#include <sofia-sip/sdp.h>

typedef struct krx_sdp krx_sdp;

struct krx_sdp {
  sdp_parser_t* parser;
  sdp_session_t* session;
  su_home_t* home;
};

int krx_sdp_init(krx_sdp* k);
int krx_sdp_parse(krx_sdp* k, const char* buf, issize_t len);
int krx_sdp_shutdown(krx_sdp* k);

#endif
