#include "krx_sdp.h"

/* --------------------------------------------------------------------------- */

/* Debug */
static const char* krx_sdp_proto_to_string(sdp_proto_e e);
static const char* krx_sdp_addrtype_to_string(sdp_addrtype_e e);
static const char* krx_sdp_nettype_to_string(sdp_nettype_e e);

/* --------------------------------------------------------------------------- */

int krx_sdp_init(krx_sdp* k) {

  if(!k) {
    printf("Error: krx_sdp_init(), invalid pointer.\n");
    return -1;
  }

  k->home = su_home_new(sizeof(su_home_t));
  if(!k->home) {
    printf("Error: krx_sdp_init(), cannot allocate a su_home_t.\n");
    return -2;
  }

  if(su_home_init(k->home) < 0) {
    printf("Error: krx_sdp_init(), cannot su_home_init().\n");
    return -3;
  }

  k->parser = NULL;
  k->session = NULL;

  return 0;
}

int krx_sdp_shutdown(krx_sdp* k) {

  if(!k) {
    printf("Error: krx_sdp_shutdown(), invalid pointer.\n");
    return -1;
  }

  if(k->parser) {
    sdp_parser_free(k->parser);
    k->parser = NULL;
  }

  if(k->home) {
    su_home_deinit(k->home);
    k->home = NULL;
  }

  return 0;
}

int krx_sdp_parse(krx_sdp* k, const char* buf, issize_t len) {
  
  if(!k) {
    printf("Error: krx_sdp_parse(), invalid pointer.\n");
    return -1;
  }

  if(k->parser) {
    printf("Error: krx_sdp_parse(), already parsed, reinitialize first. You don't need to parse multiple times for the same data.\n");
    return -2;
  }


  if(!buf) {
    printf("Error: krx_sdp_parse(), invalid buffer.\n");
    return -3;
  }

  if(len <= 0) {
    printf("Error: krx_sdp_parse(), invalid len.\n");
    return -4;
  }

  k->parser = sdp_parse(k->home, buf, len, 0);
  k->session = sdp_session(k->parser);

  if(!k->session) {
    printf("Error: krx_sdp_parse() failed: %s\n", sdp_parsing_error(k->parser));
    printf("@todo(roxlu): should we cleanup here??\n");
    return -5;
  }

  return 0;
}

/* --------------------------------------------------------------------------- */

static const char* krx_sdp_proto_to_string(sdp_proto_e e) { 
  switch(e) {
    case sdp_proto_x: return "Unknown transport";
    case sdp_proto_tcp: return "TCP";
    case sdp_proto_udp: return "UDP";
    case sdp_proto_rtp: return "RTP/AVP";
    case sdp_proto_srtp: return "RTP/SAVP";
    case sdp_proto_udptl: return "UDPTL";
    case sdp_proto_tls: return "TLS over TCP";
    case sdp_proto_any: return "wildcard";
    default: return "Unknown."; 
  }
}

static const char* krx_sdp_addrtype_to_string(sdp_addrtype_e e) {
  switch(e) {
    case sdp_addr_x: return "Unknown address type";
    case sdp_addr_ip4: return "IPv4 address";
    case sdp_addr_ip6: return "IPv6 address";
    default: return "Unknown.";
  }
}

static const char* krx_sdp_nettype_to_string(sdp_nettype_e e) {
  switch(e) {
    case sdp_net_x: return "Unknown network type.";
    case sdp_net_in: return "Internet";
    default: return "Unknown.";
  }
}
