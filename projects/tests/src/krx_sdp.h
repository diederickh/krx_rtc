/*

  krx_sdp
  -------
  Minimal SDP parser, just enough to handle and create WebRTC connections.
  Based on: https://github.com/jart/sofia-sip/blob/master/libsofia-sip-ua/sdp/sdp_parse.c

  TODO:
  -----
  - we probable want to rename the functions that parse attributes a bit... see krx_stun.c 

*/
#ifndef KRX_SDP_H
#define KRX_SDP_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#define SDP_CLONE_RTPMAPS    0x0001         /* clone all rtpmaps */
#define SDP_CLONE_CANDIDATES 0x0002         /* clone all candidates */
#define SDP_CLONE_ATTRIBUTES 0x0004         /* clone all attributes */
#define SDP_CLONE_ALL        0x000F         /* clone all possible elements */

typedef struct krx_sdp krx_sdp;
typedef struct krx_sdp_reader krx_sdp_reader;
typedef struct krx_sdp_writer krx_sdp_writer;
typedef struct krx_sdp_media krx_sdp_media;
typedef struct krx_sdp_origin krx_sdp_origin;
typedef struct krx_sdp_connection krx_sdp_connection;
typedef struct krx_sdp_attribute krx_sdp_attribute;
typedef struct krx_sdp_candidate krx_sdp_candidate;
typedef struct krx_sdp_rtpmap krx_sdp_rtpmap;
typedef enum krx_sdp_nettype krx_sdp_nettype;
typedef enum krx_sdp_addrtype krx_sdp_addrtype;
typedef enum krx_sdp_proto krx_sdp_proto;
typedef enum krx_sdp_media_type krx_sdp_media_type;
typedef enum krx_sdp_candidate_type krx_sdp_candidate_type;
typedef enum krx_sdp_transport_type krx_sdp_transport_type;
typedef enum krx_sdp_mode krx_sdp_mode;

enum krx_sdp_nettype {
  SDP_NET_NONE = 0,
  SDP_NET_IN,            /* The one and only internet */
};

enum krx_sdp_addrtype { 
  SDP_ADDR_NONE = 0,
  SDP_IP4, 
  SDP_IP6,
};

enum krx_sdp_mode {
  SDP_MODE_NONE= 0,
  SDP_SENDONLY,
  SDP_RECVONLY,
  SDP_SENDRECV
};

enum krx_sdp_transport_type {
  SDP_TRANSPORT_NONE = 0,
  SDP_TCP,
  SDP_UDP,
};

enum krx_sdp_proto {
  SDP_PROTO_NONE = 0,
  SDP_UDP_RTP_SAVPF,
};

enum krx_sdp_media_type {
  SDP_MEDIA_TYPE_NONE = 0,
  SDP_VIDEO,
  SDP_AUDIO, 
};

enum krx_sdp_candidate_type {
  SDP_CANDIDATE_TYPE_NONE = 0,
  SDP_HOST,
  SDP_SRFLX,
  SDP_PRFLX,
  SDP_RELAY,
};

struct krx_sdp_attribute {
  char* name;
  char* value;
  krx_sdp_attribute* next;
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

struct krx_sdp_candidate {
  char* foundation;
  uint32_t component_id;
  krx_sdp_transport_type transport;  
  uint64_t priority;
  char* addr;
  uint32_t port;
  char* raddr;
  uint32_t rport;
  krx_sdp_candidate_type type;
  krx_sdp_candidate* next;
};

struct krx_sdp_rtpmap {
  uint32_t type;
  krx_sdp_rtpmap* next;
};

struct krx_sdp_media { 
  uint16_t port;
  uint8_t num_ports;
  krx_sdp_proto proto;
  krx_sdp_media_type type;
  krx_sdp_mode mode;
  krx_sdp_attribute* attributes;
  krx_sdp_rtpmap* rtpmap;
  krx_sdp_candidate* candidates;
  krx_sdp_media* next;
};

struct krx_sdp { 
  char* version;
  krx_sdp_mode mode;
  krx_sdp_origin* origin;
  krx_sdp_media* media;
  krx_sdp_attribute* attributes;
};

struct krx_sdp_reader {
  krx_sdp* session;                             /* after reading a string this will hold the parsed sdp */
  char* buffer;                                 /* the buffer which is passed to krx_sdp_parse; we copy it. */
  uint8_t has_error;                            /* is set to 1 when something goes wrong with parseing */
  krx_sdp_attribute** curr_attr;                /* the attribute list that we need to append to */
  krx_sdp_media* curr_media;                    /* is set to the last media element we created/parsed */
};

struct krx_sdp_writer {
  krx_sdp* session;                             /* the session that we generate */
};

/* allocate krx_sdp_* types */
krx_sdp* krx_sdp_alloc();
krx_sdp_reader* krx_sdp_reader_alloc();
krx_sdp_writer* krx_sdp_writer_alloc();
krx_sdp_media* krx_sdp_media_alloc();
krx_sdp_origin* krx_sdp_origin_alloc();
krx_sdp_connection* krx_sdp_connection_alloc();
krx_sdp_attribute* krx_sdp_attribute_alloc();
krx_sdp_rtpmap* krx_sdp_rtpmap_alloc();
krx_sdp_candidate* krx_sdp_candidate_alloc();

/* deallocate krx_sdp_* types; these also nicely cleanup the members of the types. */
void krx_sdp_dealloc(krx_sdp* sdp);
void krx_sdp_reader_dealloc(krx_sdp_reader* reader);
void krx_sdp_writer_dealloc(krx_sdp_writer* writer);
void krx_sdp_media_dealloc(krx_sdp_media* m);
void krx_sdp_origin_dealloc(krx_sdp_origin* o);
void krx_sdp_connection_dealloc(krx_sdp_connection* conn);
void krx_sdp_candidate_dealloc(krx_sdp_candidate* cand);
void krx_sdp_rtpmap_dealloc(krx_sdp_rtpmap* map);
void krx_sdp_attribute_dealloc(krx_sdp_attribute* attr);

/* parsing and manipulating */
int krx_sdp_read(krx_sdp_reader* reader, char* buf, int nbytes);
int krx_sdp_remove_candidates(krx_sdp_media* m);                                        /* removes and deallocs all candidats from the given media */

int krx_sdp_clone_media(krx_sdp_writer* writer, krx_sdp_media* media, uint32_t what);   /* clone several elements from the given media element */
krx_sdp_attribute* krx_sdp_find_attribute(krx_sdp* session, char* name, int any); /* find an attribute for the given name, when `any=1` we will also look for the attributes of the media elements */
krx_sdp_attribute* krx_sdp_media_find_attribute(krx_sdp_media* media, char* name); /* find a media attribute by name */
int krx_sdp_add_media(krx_sdp* sdp, krx_sdp_media* m); /* @todo(roxlu): test krx_sdp_add_media */
int krx_sdp_media_to_string(krx_sdp_media* m, char* buf, int nbytes); /* @todo(roxlu): media_to_string, check size. */
int krx_sdp_attributes_to_string(krx_sdp_attribute* a, char* buf, int nbytes); /* @todo(roxlu): attributes_to_string, check size. */
int krx_sdp_candidates_to_string(krx_sdp_candidate* c, char* buf, int nbytes); /* @todo(roxlu): candidates_to_string, check size. */
char* krx_sdp_media_type_to_string(krx_sdp_media_type type);
char* krx_sdp_proto_type_to_string(krx_sdp_proto proto);
char* krx_sdp_transport_type_to_string(krx_sdp_transport_type trans);
char* krx_sdp_candidate_type_to_string(krx_sdp_candidate_type type);
char* krx_sdp_mode_to_string(krx_sdp_mode mode);

int krx_sdp_print(krx_sdp* sdp, char* buf, int nbytes);

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
