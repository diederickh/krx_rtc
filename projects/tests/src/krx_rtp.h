/*

  KRX_RTP
  -------
  Experimental code to parse RTP messages.

  References:
  -----------
  - http://www.ffmpeg.org/doxygen/2.1/rtpdec__vp8_8c_source.html
  - http://doubango.googlecode.com/svn-history/r653/branches/2.0/doubango/tinyDAV/src/codecs/vpx/tdav_codec_vp8.c

*/
#ifndef ROXLU_KRX_RTP_H
#define ROXLU_KRX_RTP_H

#include <stdio.h>
#include <stdlib.h>

typedef struct krx_rtp krx_rtp_t;
typedef struct krx_rtp_vp8 krx_rtp_vp8_t;


struct krx_rtp_vp8 {                    /* we're only implementing vp8 rtp now, this represents the packets as described in http://tools.ietf.org/html/draft-ietf-payload-vp8-11 */
  
  /* required */
  uint8_t X;                            /* extended controlbits present */
  uint8_t N;                            /* (non-reference frame)  when set to 1 this frame can be discarded */
  uint8_t S;                            /* start of VP8 partition */
  uint8_t PID;                          /* partition index */

  /* second row (is optional) */
  uint8_t I;                            /* 1 if PictureID is present */
  uint8_t L;                            /* 1 if TL0PICIDX is present */
  uint8_t T;                            /* 1 if TID is present */ 
  uint8_t K;                            /* 1 if KEYIDX is present */
  uint8_t PictureID;                    /* 8 or 16 bits, picture ID */
  uint8_t TL0PICIDX;                    /* 8 bits temporal level zero index */

  uint8_t* buf;
};

struct krx_rtp { 

  /* header info */
  uint8_t V_version;
  uint8_t padding;
  uint8_t extension;
  uint8_t csrc_count;
  uint8_t marker;                        /* Set for the very last packet of each encoded frame in line with the normal use of the M bit in video formats. For VP8 this will be set to 1 when the last packet for a frame is received. */
  uint8_t payload_type;
  uint16_t sequence_number;
  uint32_t timestamp;
  uint32_t ssrc;

  krx_rtp_vp8_t vp8;                   /* vp8 header */
};

int krx_rtp_init(krx_rtp_t* k);
int krx_rtp_decode(krx_rtp_t* k, uint8_t* buf, int len);
int krx_rtp_decode_vp8(krx_rtp_vp8_t* v, uint8_t* buf, int len); /* decode a vp8 rtp header */
uint16_t krx_rtp_read_u16(uint8_t* ptr);
uint32_t krx_rtp_read_u32(uint8_t* ptr);

#endif
