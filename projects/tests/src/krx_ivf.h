/*

  krx_ivf
  -------
  Based on http://www.webmproject.org/docs/vp8-sdk/example__simple__encoder.html the
  krx_ivf code is used to store VPX frames into a very simple file format that can
  be used with avconv to mux it into a playable format. Created this for testing the 
  RTP-VP8 stream.

  
 */
#ifndef ROXLU_KRX_IVF_H
#define ROXLU_KRX_IVF_H

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

typedef struct krx_ivf krx_ivf_t;

struct krx_ivf {
  /* generic */
  FILE* fp;

  /* ivf header info */
  uint16_t version;
  uint16_t width;
  uint16_t height; 
  uint32_t timebase_den;
  uint32_t timebase_num;
  uint64_t num_frames;
};

int krx_ivf_init(krx_ivf_t* k);                                  /* initializes all members to initial values */
int krx_ivf_create(krx_ivf_t* k);
int krx_ivf_write_header(krx_ivf_t* k);
int krx_ivf_write_frame(krx_ivf_t* k, uint64_t timestamp, uint8_t* data, uint32_t len);
int krx_ivf_write_u8(krx_ivf_t* k, uint8_t data);
int krx_ivf_write_u16(krx_ivf_t* k, uint16_t data);
int krx_ivf_write_u32(krx_ivf_t* k, uint32_t data);
int krx_ivf_write_u64(krx_ivf_t* k, uint64_t data);
int krx_ivf_write(krx_ivf_t* k, uint8_t* data, uint32_t len);
int krx_ivf_destroy(krx_ivf_t* k);

int krx_ivf_open(krx_ivf_t* k);
int krx_ivf_read_header(krx_ivf_t* k);
int krx_ivf_read_frame(krx_ivf_t* k);
uint8_t krx_ivf_read_u8(krx_ivf_t* k);
uint16_t krx_ivf_read_u16(krx_ivf_t* k);
uint32_t krx_ivf_read_u32(krx_ivf_t* k);
uint64_t krx_ivf_read_u64(krx_ivf_t* k);

#endif
