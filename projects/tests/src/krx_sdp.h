/*
  
  krx_sdp
  -------
  Experimental sdp handler using pjsip.

  References:
  - https://trac.pjsip.org/repos/wiki/Using_Standalone_ICE

 */
#ifndef KRX_SDP_H
#define KRX_SDP_H

#include <pjlib.h>
#include <pjlib-util.h>
#include <pjmedia/sdp.h>

#define KRX_SDP_MEDIA_NONE 0
#define KRX_SDP_MEDIA_VIDEO 1
#define KRX_SDP_MEDIA_AUDIO 2

#define KRX_SDP_STR(x) #x
#define KRX_SDP_TO_STR(x) KRX_SDP_STR(x)
#define KRX_SDP_DEF_CASE(x) case x: { return KRX_SDP_TO_STR(x); }

typedef struct krx_sdp krx_sdp;
typedef struct krx_sdp_media krx_sdp_media;
typedef struct krx_sdp_candidate krx_sdp_candidate;

struct krx_sdp_media {
  int index; /* index in the session->media of krx_sdp */
};

typedef enum {
  KRX_SDP_UDP = 1,
  KRX_SDP_TCP
} krx_sdp_transport_type;

typedef enum { 
  KRX_SDP_HOST = 1,
  KRX_SDP_SRFLX, 
  KRX_SDP_RELAY, 
  KRX_SDP_PRFLX
} krx_sdp_candidate_type;

struct krx_sdp_candidate {
  uint8_t component_id;                                                                                       /* 1 = RTP, 2 = RTCP, see RFC5245 */
  uint32_t prio;
  uint16_t port;
  char host[32];
  char foundation[32];
  krx_sdp_transport_type transport_type;
  krx_sdp_candidate_type candidate_type;
};

struct krx_sdp {
  pj_caching_pool cp;
  pj_pool_t* pool;
  pjmedia_sdp_session* session;
};

int krx_sdp_init(krx_sdp* k);                                                                                   /* initialze a krx_sdp */
int krx_sdp_parse(krx_sdp* k, const char* buf, int len);                                                        /* as len, pass strlen(buf) */
int krx_sdp_get_media(krx_sdp* k, krx_sdp_media m[], int nmedia, int type);                                     /* get nmedia handles for the given type; on sucess we return the found media types */
int krx_sdp_get_ufrag(krx_sdp* k, char* out, int nbytes);                                                       /* get ice-ufrag from general part */
int krx_sdp_get_pwd(krx_sdp* k, char* out, int nbytes);                                                         /* get ice-pwd from general sdp part */
int krx_sdp_get_media_ufrag(krx_sdp* k, krx_sdp_media* m, char* out, int nbytes);                               /* get the ice-ufrag for the given media */
int krx_sdp_get_media_pwd(krx_sdp* k, krx_sdp_media* m, char* out, int nbytes);                                 /* get the ice-ufrag for the given media */
int krx_sdp_get_candidates(krx_sdp* k, krx_sdp_candidate* out, int ntotal);                                     /* get candidates from the general part in the sdp */
int krx_sdp_get_media_candidates(krx_sdp* k, krx_sdp_media* m, int nmedia, krx_sdp_candidate* out, int ntotal); /* get candidates from a specific media element */
int krx_sdp_print_candidate(krx_sdp_candidate* c);                                                              /* print some verbose info about the given candidate */
int krx_sdp_shutdown(krx_sdp* k);                                                                               /* cleanup + free the krx_sdp */

const char* krx_sdp_candidate_type_to_string(krx_sdp_candidate_type type);
const char* krx_sdp_transport_type_to_string(krx_sdp_transport_type type);

/*
  Example sdp
  -------------
  v=0
  o=- 9115171964812349169 2 IN IP4 127.0.0.1
  s=-
  t=0 0
  a=group:BUNDLE audio video
  a=msid-semantic: WMS BfXlgpFTeJeijYiI0gub1fNwTHtKTMGIceh0
  m=audio 1 RTP/SAVPF 111 103 104 0 8 106 105 13 126
  c=IN IP4 0.0.0.0
  a=rtcp:1 IN IP4 0.0.0.0
  a=ice-ufrag:ElGLxj4oVCWCY7XF
  a=ice-pwd:rZkUhEjwRHkXoE7iiLgzQwyq
  a=ice-options:google-ice
  a=fingerprint:sha-256 3E:4F:43:C0:5E:70:3B:9A:33:75:50:03:5E:49:12:A4:C8:A8:E6:E1:56:27:E7:40:2B:D3:F1:D6:7E:A7:39:23
  a=setup:actpass
  a=mid:audio
  a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level
  a=recvonly
  a=rtcp-mux
  a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:FafwVEfW6GkkbphOa7L0X3ASOCwl54oh5CPArTAH
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
  m=video 1 RTP/SAVPF 100 116 117
  c=IN IP4 0.0.0.0
  a=rtcp:1 IN IP4 0.0.0.0
  a=ice-ufrag:ElGLxj4oVCWCY7XF
  a=ice-pwd:rZkUhEjwRHkXoE7iiLgzQwyq
  a=ice-options:google-ice
  a=fingerprint:sha-256 3E:4F:43:C0:5E:70:3B:9A:33:75:50:03:5E:49:12:A4:C8:A8:E6:E1:56:27:E7:40:2B:D3:F1:D6:7E:A7:39:23
  a=setup:actpass
  a=mid:video
  a=extmap:2 urn:ietf:params:rtp-hdrext:toffset
  a=extmap:3 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time
  a=sendrecv
  a=rtcp-mux
  a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:FafwVEfW6GkkbphOa7L0X3ASOCwl54oh5CPArTAH
  a=rtpmap:100 VP8/90000
  a=rtcp-fb:100 ccm fir
  a=rtcp-fb:100 nack
  a=rtcp-fb:100 goog-remb
  a=rtpmap:116 red/90000
  a=rtpmap:117 ulpfec/90000
  a=ssrc:2050584804 cname:Dl9AsgInwvhYAhLQ
  a=ssrc:2050584804 msid:BfXlgpFTeJeijYiI0gub1fNwTHtKTMGIceh0 e445c1fd-33ca-4075-9bb9-e8d2938b1186
  a=ssrc:2050584804 mslabel:BfXlgpFTeJeijYiI0gub1fNwTHtKTMGIceh0
  a=ssrc:2050584804 label:e445c1fd-33ca-4075-9bb9-e8d2938b1186
  
  ----

  v=0
  o=Mozilla-SIPUA-29.0 9417 0 IN IP4 0.0.0.0
  s=SIP Call
  t=0 0
  a=ice-ufrag:f4e5dd71
  a=ice-pwd:a540c63e17673bad5c97aaafe7e85840
  a=fingerprint:sha-256 3E:4F:43:C0:5E:70:3B:9A:33:75:50:03:5E:49:12:A4:C8:A8:E6:E1:56:27:E7:40:2B:D3:F1:D6:7E:A7:39:23
  m=video 5493 RTP/SAVPF 120
  c=IN IP4 84.105.186.141
  a=rtpmap:120 VP8/90000
  a=sendrecv
  a=rtcp-fb:120 nack
  a=rtcp-fb:120 nack pli
  a=rtcp-fb:120 ccm fir
  a=setup:actpass
  a=candidate:0 1 UDP 2130379007 192.168.0.194 2233 typ host
  a=candidate:1 1 UDP 1694236671 84.105.186.141 5493 typ srflx raddr 192.168.0.194 rport 59402
  a=candidate:0 2 UDP 2130379006 192.168.0.194 65529 typ host
  a=candidate:1 2 UDP 1694236670 84.105.186.141 5494 typ srflx raddr 192.168.0.194 rport 65529
  a=rtcp-mux

 */

#endif
