/*

  krx_sdp
  -------
  Minimal SDP parser, just enough to handle and create WebRTC connections.
  Based on: https://github.com/jart/sofia-sip/blob/master/libsofia-sip-ua/sdp/sdp_parse.c

 */
#ifndef KRX_SDP_H
#define KRX_SDP_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

typedef struct krx_sdp krx_sdp;
typedef struct krx_sdp_media krx_sdp_media;
typedef struct krx_sdp_origin krx_sdp_origin;
typedef struct krx_sdp_connection krx_sdp_connection;
typedef enum krx_sdp_nettype krx_sdp_nettype;
typedef enum krx_sdp_addrtype krx_sdp_addrtype;

enum krx_sdp_nettype {
  SDP_NET_NONE = 0,
  SDP_NET_IN            /* The one and only internet */
};

enum krx_sdp_addrtype { 
  SDP_ADDR_NONE = 0,
  SDP_IP4, 
  SDP_IP6
};

struct krx_sdp_connection { 
  krx_sdp_nettype net_type;
  krx_sdp_addrtype addr_type;
  char* address;
  uint32_t ttl;
  uint8_t is_multi_cast;
  uint32_t num_groups;
};

struct krx_sdp_origin { 
  char* username;
  uint64_t sess_id;
  uint64_t sess_version;
  krx_sdp_nettype net_type;
  krx_sdp_addrtype addr_type;
  krx_sdp_connection *address;
};

struct krx_sdp_media { 
  krx_sdp_media* next;
};

struct krx_sdp { 
  char* sdp;                                     /* the buffer which is passed to krx_sdp_parse; we copy it. */
  char* version;
  krx_sdp_origin* origin;
  krx_sdp_media* media;
  
  uint8_t has_parse_error;
};

/* memory management */
krx_sdp* krx_sdp_alloc();
krx_sdp_media* krx_sdp_media_alloc();
krx_sdp_origin* krx_sdp_origin_alloc();
krx_sdp_connection* krx_sdp_connection_alloc();

void krx_sdp_dealloc(krx_sdp* sdp);

/* parsing */
int krx_sdp_parse(krx_sdp* sdp, char* buf, int nbytes);

/* generating */
int krx_sdp_add_media(krx_sdp* sdp, krx_sdp_media* m);

/*

v=0
o=- 5138404983558149901 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE audio video
a=msid-semantic: WMS UKnNdR7T65ZwPUfXmoor6THF7oWmsmPKPBn6
m=audio 32291 RTP/SAVPF 111 103 104 0 8 106 105 13 126
c=IN IP4 84.105.186.141
a=rtcp:32291 IN IP4 84.105.186.141
a=candidate:4252876256 1 udp 2113937151 192.168.0.194 60607 typ host generation 0
a=candidate:4252876256 2 udp 2113937151 192.168.0.194 60607 typ host generation 0
a=candidate:2083896148 1 udp 1845501695 84.105.186.141 32291 typ srflx raddr 192.168.0.194 rport 60607 generation 0
a=candidate:2083896148 2 udp 1845501695 84.105.186.141 32291 typ srflx raddr 192.168.0.194 rport 60607 generation 0
a=candidate:3019784464 1 tcp 1509957375 192.168.0.194 0 typ host generation 0
a=candidate:3019784464 2 tcp 1509957375 192.168.0.194 0 typ host generation 0
a=ice-ufrag:1EeLhAYpIOrketY7
a=ice-pwd:kxZ6Csm+6jl8M9dI4kdAr/hi
a=ice-options:google-ice
a=fingerprint:sha-256 33:AE:3A:BA:68:54:D9:E2:F7:86:75:14:09:AF:86:D4:E5:B0:2E:E2:7A:27:8A:D4:FD:1E:AD:54:29:9D:2C:33
a=setup:actpass
a=mid:audio
a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level
a=recvonly
a=rtcp-mux
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:psZ7URAl2BxU9rBXMW6TvjNOUVpSFjnh6qaqu8pa
a=rtpmap:111 opus/48000/2
a=fmtp:111 minptime=10
a=rtpmap:103 ISAC/16000
a=rtpmap:104 ISAC/32000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:106 CN/32000
a=rtpmap:105 CN/16000
a=rtpmap:13 CN/8000
a=rtpmap:126 telephone-event/8000
a=maxptime:60
m=video 32291 RTP/SAVPF 100 116 117
c=IN IP4 84.105.186.141
a=rtcp:32291 IN IP4 84.105.186.141
a=candidate:4252876256 1 udp 2113937151 192.168.0.194 60607 typ host generation 0
a=candidate:4252876256 2 udp 2113937151 192.168.0.194 60607 typ host generation 0
a=candidate:2083896148 1 udp 1845501695 84.105.186.141 32291 typ srflx raddr 192.168.0.194 rport 60607 generation 0
a=candidate:2083896148 2 udp 1845501695 84.105.186.141 32291 typ srflx raddr 192.168.0.194 rport 60607 generation 0
a=candidate:3019784464 1 tcp 1509957375 192.168.0.194 0 typ host generation 0
a=candidate:3019784464 2 tcp 1509957375 192.168.0.194 0 typ host generation 0
a=ice-ufrag:1EeLhAYpIOrketY7
a=ice-pwd:kxZ6Csm+6jl8M9dI4kdAr/hi
a=ice-options:google-ice
a=fingerprint:sha-256 33:AE:3A:BA:68:54:D9:E2:F7:86:75:14:09:AF:86:D4:E5:B0:2E:E2:7A:27:8A:D4:FD:1E:AD:54:29:9D:2C:33
a=setup:actpass
a=mid:video
a=extmap:2 urn:ietf:params:rtp-hdrext:toffset
a=extmap:3 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time
a=sendrecv
a=rtcp-mux
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:psZ7URAl2BxU9rBXMW6TvjNOUVpSFjnh6qaqu8pa
a=rtpmap:100 VP8/90000
a=rtcp-fb:100 ccm fir
a=rtcp-fb:100 nack
a=rtcp-fb:100 goog-remb
a=rtpmap:116 red/90000
a=rtpmap:117 ulpfec/90000
a=ssrc:1646927809 cname:mnNJ7EUL2KVbJ7he
a=ssrc:1646927809 msid:UKnNdR7T65ZwPUfXmoor6THF7oWmsmPKPBn6 d8c32ee1-6d2f-48a1-a030-3583240f4136
a=ssrc:1646927809 mslabel:UKnNdR7T65ZwPUfXmoor6THF7oWmsmPKPBn6
a=ssrc:1646927809 label:d8c32ee1-6d2f-48a1-a030-3583240f4136
    


 */

#endif
