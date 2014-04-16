/*
  
  krx_ice
  --------

  Experimental code to implement the bare bones for an ICE implementation
  so we can receive and send video/audio data to another webrtc endpoint.
  This code is used to discover the ICE protocol(s).

  For ease of development we're not yet decoupling the networking layer at 
  this point.. using libuv for that. 

  References
  ----------
  - ice implementation: https://github.com/korobool/linphonecdbus/blob/309b03cb76734d54630a42300cf0a3e9b8710d49/mediastreamer2/src/voip/ice.c
 */

#ifndef KRX_ICE_H
#define KRX_ICE_H

#include "krx_stun.h"
#include "krx_sdp.h"
#include "krx_memory.h"
#include <uv.h>

typedef struct krx_ice krx_ice;
typedef struct krx_ice_conn krx_ice_conn;

struct krx_ice_conn {                               /* represents a connections/socket */
  uv_udp_t sock;
  krx_ice_conn* next;
};

struct krx_ice {                                    /* the ice context */
  krx_ice_conn* connections;
  krx_sdp_writer* sdp;
  krx_stunc* stunc;
  krx_mem* mem;                                     /* very simplistic memory management */
  uv_udp_t server;
  struct sockaddr_in raddr;
};

krx_ice* krx_ice_alloc();
krx_ice_conn* krx_ice_conn_alloc();
int krx_ice_start(krx_ice* ice); 
void krx_ice_update(krx_ice* ice);


#endif
