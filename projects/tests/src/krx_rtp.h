/*

  KRX_RTP
  -------
  Experimental code to parse RTP messages.

  References:
  -----------
  - http://www.ffmpeg.org/doxygen/2.1/rtpdec__vp8_8c_source.html
  - http://doubango.googlecode.com/svn-history/r653/branches/2.0/doubango/tinyDAV/src/codecs/vpx/tdav_codec_vp8.c

  Old version:
  -------------
  - Before cleanup: https://gist.github.com/roxlu/f816a3da4861befc21db
  - First success of a recording: https://gist.github.com/roxlu/3eacd69c3389dd0784f7

*/
#ifndef ROXLU_KRX_RTP_H
#define ROXLU_KRX_RTP_H

#define RTP_NUM_PACKETS 128

#include <stdio.h>
#include <stdlib.h>
#include "krx_ivf.h"

typedef struct krx_rtp krx_rtp_t;
typedef struct krx_rtp_vp8 krx_rtp_vp8_t;


struct krx_rtp_vp8 {                    /* we're only implementing vp8 rtp now, this represents the packets as described in http://tools.ietf.org/html/draft-ietf-payload-vp8-11 */
  
  uint8_t is_free;

  /* header info */
  uint8_t version;
  uint8_t padding;
  uint8_t extension;
  uint8_t csrc_count;
  uint8_t marker;                        /* Set for the very last packet of each encoded frame in line with the normal use of the M bit in video formats. For VP8 this will be set to 1 when the last packet for a frame is received. */
  uint8_t payload_type;
  uint16_t sequence_number;
  uint32_t timestamp;
  uint32_t ssrc;

  /* required */
  uint8_t X;                            /* extended controlbits present */
  uint8_t N;                            /* (non-reference frame)  when set to 1 this frame can be discarded */
  uint8_t S;                            /* start of VP8 partition */
  uint8_t PID;                          /* partition index */

  /* 2nd second row Payload Descriptor (is optional) */
  uint8_t I;                            /* 1 if PictureID is present */
  uint8_t L;                            /* 1 if TL0PICIDX is present */
  uint8_t T;                            /* 1 if TID is present */ 
  uint8_t K;                            /* 1 if KEYIDX is present */
  uint8_t PictureID;                    /* 8 or 16 bits, picture ID */
  uint8_t TL0PICIDX;                    /* 8 bits temporal level zero index */

  /* 3rd row Payload Descriptor */
  uint8_t M;                            /* Extension flag; must be present if I bit == 1. If set, the PictureID field must contains 16 bits, else 8*/

  /* payload header */
  uint8_t P;                             /* 0 if current frame is a key frame, otherwise 1 */

  uint8_t buf[2048];                    /* buffer container the actual frame data; Payload-Descriptor stripped */
  int nbytes;                           /* number of bytes in the buffer */
};

struct krx_rtp { 
  krx_ivf_t ivf;                       /* just for debugging; used to record the vp8 data */
  krx_rtp_vp8_t vp8;                   /* vp8 header */
  krx_rtp_vp8_t vp8_packets[RTP_NUM_PACKETS];

  /* testing with acummulation buffer */
  uint8_t buf[1024*1024];   /* accumulation buffer */
  uint16_t prev_seq;        /* previous sequence number */
  uint32_t pos;             /* position in the buffer */
  uint32_t nsize;           /* the size of the frame as we extract from the first partition */
};

int krx_rtp_init(krx_rtp_t* k);
int krx_rtp_decode(krx_rtp_t* k, uint8_t* buf, int len);
int krx_rtp_decode_vp8(krx_rtp_t* k, krx_rtp_vp8_t* v, uint8_t* buf, int len); /* decode a vp8 rtp header */
krx_rtp_vp8_t* krx_rtp_find_free_vp8_packet(krx_rtp_t* k);
int krx_rtp_vp8_init(krx_rtp_vp8_t* v);
uint16_t krx_rtp_read_u16(uint8_t* ptr);
uint32_t krx_rtp_read_u32(uint8_t* ptr);
uint16_t krx_rtp_read_u16_picture_id(uint8_t* ptr);

void krx_rtp_print(krx_rtp_vp8_t* k);

/* frame reconstruction */
int krx_rtp_reconstruct_frames(krx_rtp_t* k, uint8_t* buf, int len);
krx_rtp_vp8_t* krx_rtp_find_packet_with_timestamp(krx_rtp_t* k);
int krx_rtp_find_packets_with_timestamp(krx_rtp_t* k, uint32_t timestamp, krx_rtp_vp8_t* result[], int len);
#endif
