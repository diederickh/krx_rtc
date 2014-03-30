/*

  KRX_RTP
  -------
  Experimental code to parse RTP messages.

*/
#ifndef ROXLU_KRX_RTP_H
#define ROXLU_KRX_RTP_H

#include <stdio.h>
#include <stdlib.h>

typedef struct krx_rtp krx_rtp_t;
typedef struct krx_rtp_vp8 krx_rtp_vp8_t;


struct krx_rtp_vp8 {                    /* we're only implementing vp8 rtp now, this represents the packets as described in http://tools.ietf.org/html/draft-ietf-payload-vp8-11 */
  
  /* required */
  uint8_t extended_control;
  uint8_t non_reference_frame;          /* when set to 1 this frame can be discarded */
  uint8_t start_of_vp8;
  uint8_t partition_index;              /* first partition contains motions vectors */

  /* optional 1 */
  uint8_t picture_id_present;
  uint8_t pic_idx_present;
  uint8_t tid_present;
  uint8_t key_idx_present;
  uint16_t picture_id;
  
};

struct krx_rtp { 

  /* header info */
  uint8_t version;
  uint8_t padding;
  uint8_t extension;
  uint8_t csrc_count;
  uint8_t marker;                        /* for VP8 this will be set to 1 when the last packet for a frame is received. */
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
