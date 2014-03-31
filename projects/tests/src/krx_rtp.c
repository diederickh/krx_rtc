#include "krx_rtp.h"

int krx_rtp_init(krx_rtp_t* k) {
  return 0;
}

int krx_rtp_decode(krx_rtp_t* k, uint8_t* buf, int len) {
  
  if(!buf) {
    printf("Error: krx_rtp_decode(), invalid buffer.\n");
    return -1;
  }

  if(len <= 0) {
    printf("Error: krx_rtp_decode(), invalid len.\n");
    return -2;
  }

  if(len < 12) {
    printf("Error: krx_rtp_decode(), but should be at least 12 bytes.\n");
    return -3;
  }

  /* RTP Header */
  k->version = (buf[0] & 0xC0) >> 6;
  k->padding = (buf[0] & 0x20) >> 4;
  k->extension = (buf[0] & 0x10) >> 3;
  k->csrc_count = (buf[0] & 0x0F);
  k->marker = (buf[1] & 0x80) >> 7;
  k->payload_type = (buf[1] & 0x7F);
  k->sequence_number = krx_rtp_read_u16(buf+2); 
  k->timestamp = krx_rtp_read_u32(buf+4);
  k->ssrc = krx_rtp_read_u32(buf+8);

  // @todo(roxlu): handle csrc_count > 0
  if(k->csrc_count != 0) {
    printf("Error: we're only handling a simple rtp packet now. none with csrc_count > 0 (got: %d).\n", k->csrc_count);
    exit(EXIT_FAILURE);
  }

#if 1
  printf("-\n");
  printf("Version: %d\n", k->version);
  printf("Padding: %d\n", k->padding);
  printf("Extension: %d\n", k->extension);
  printf("CSRC count: %d\n", k->csrc_count);
  printf("Marker: %d\n", k->marker);
  printf("Payload type: %d\n", k->payload_type);
  printf("Sequence number: %d\n", k->sequence_number);
  printf("Timestamp: %u\n", k->timestamp);
  printf("SSRC: %u\n", k->ssrc);
#endif

  /* VP8 */
  int r = krx_rtp_decode_vp8(&k->vp8, buf+12, (len - 12));
  if(r < 0) {
    return -4;
  }

  return (12 + r); // 12 basic header.
}

int krx_rtp_decode_vp8(krx_rtp_vp8_t* v, uint8_t* buf, int len) {

  if(len < 6) {
    printf("Error: krx_rtp_decode_vp8(), cannot decode; which should have at least one byte.\n");
    return -1;
  }

  int pos = 0;
  /*
  v->extended_control = (buf[pos] & 0x80) >> 7;
  v->non_reference_frame = (buf[pos] & 0x20) >> 5;
  v->start_of_vp8 = (buf[pos] & 0x10) >> 4;
  v->partition_index = (buf[pos] & 0x07);
  */

  v->X = (buf[pos] & 0x80) >> 7;
  v->N = (buf[pos] & 0x20) >> 5;
  v->S = (buf[pos] & 0x10) >> 4;
  v->PID = (buf[pos] & 0x07);

  /*
  v->picture_id_present = 0;
  v->pic_idx_present = 0;
  v->tid_present = 0;
  v->key_idx_present = 0;
  v->picture_id = 0;
  */
  v->I = 0;
  v->L = 0;
  v->K = 0;
  v->PictureID = 0;
  v->TL0PICIDX = 0;

  pos = 1;

  if(v->X == 1) {
    /*
    v->picture_id_present = (buf[pos] & 0x80) >> 7;
    v->pic_idx_present = (buf[pos] & 0x40) >> 6;
    v->tid_present = (buf[pos] & 0x20) >> 5;
    v->key_idx_present = (buf[pos] & 0x10) >> 4;
    */
    v->I = (buf[pos] & 0x80) >> 7;
    v->L = (buf[pos] & 0x40) >> 6;
    v->T = (buf[pos] & 0x20) >> 5;
    v->K = (buf[pos] & 0x10) >> 4;
  }

  if(v->I == 1) {

    pos = 2;

    uint8_t ext_flag = (buf[pos] & 0x80) >> 7;
    uint8_t* dest_ptr = (uint8_t*)&v->PictureID;
    if(ext_flag == 1) {
      dest_ptr[0] = buf[pos + 1];
      dest_ptr[1] = (buf[pos] & 0x80);
    }
    else {
      printf("Error: krx_rtp_decode_vp8, not implement a 7bit picture id yet.\n");
      return -2;
    }

    pos = 4;
  }

  // @todo(roxlu): we only implement a very basic vp8 decoder:
  if(v->T == 1) {
    printf("Error: krx_rtp_decode_vp8(), not handling tid_present yet.\n");
    return -3;
  }
  if(v->K == 1) {
    printf("Error: krx_rtp_decode_vp8(), not handling key_idx_present yet.\n");
    return -4;
  }

#if 1
  printf("vp8 Extended Control: %d\n", v->X);
  printf("vp8 Non Reference Frame: %d\n", v->N);
  printf("vp8 Start of VP8 payload: %d\n", v->S);
  printf("vp8 Partition Index: %d\n", v->PID);
  printf("vp8 Picture ID Present: %d\n", v->I);
  printf("vp8 Pic IDX Present (TL0PICIDX): %d\n", v->L);
  printf("vp8 TID Present: %d\n", v->T);
  printf("vp8 Key IDX Present: %d\n", v->K);
  printf("vp8 Picture ID: %u\n", v->PictureID);
#endif

  /* VP8 Payload Header */
  printf("--\n");
  if(v->S == 1 && v->PID == 0) {
    printf("++ \n");
    //printf("======= VP8 Payload Header =======\n");
    uint8_t size0 = (buf[pos] & 0xE0) >> 3;
    uint8_t size1 = buf[pos + 1];
    uint8_t size2 = buf[pos + 2];
    int nbytes = (size0) + (8 * size1) + (2048 * size2);
    printf("vp8 size0: %d, size1: %d, size2: %d, number of bytes for this frame: %d, len: %d\n", size0, size1, size2, nbytes, len);

    int bytes_needed = nbytes + 6;
    if((len - bytes_needed) <= 0) {
      printf("Error: not enough bytes received yet.\n");
      return -6;
    }

    pos += 2 + nbytes;
  }

  return pos;
}

uint16_t krx_rtp_read_u16(uint8_t* ptr) {
  uint16_t r = 0;
  uint8_t* p = (uint8_t*)&r;
  p[0] = ptr[1];
  p[1] = ptr[0];
  return r;
}

uint32_t krx_rtp_read_u32(uint8_t* ptr) {
  uint32_t* pp = (uint32_t*)ptr;
  uint32_t r = 0;
  uint8_t* p = (uint8_t*)&r;
  p[0] = ptr[3];
  p[1] = ptr[2];
  p[2] = ptr[1];
  p[3] = ptr[0];
  return r;
}
