#include <assert.h>
#include "krx_ivf.h"

int krx_ivf_init(krx_ivf_t* k) {
  k->version = 0;
  k->width = 0;
  k->height = 0;
  k->timebase_den = 0;
  k->timebase_num = 0;
  k->num_frames = 0;
  k->fp = NULL;
  return 0;
}

int krx_ivf_create(krx_ivf_t* k) {
  assert(k);
  assert(k->width != 0);
  assert(k->height != 0);
  assert(k->timebase_den != 0);
  assert(k->timebase_num != 0);
  assert(k->num_frames == 0);
  
  k->fp = fopen("test.ivf", "wb");
  if(!k->fp) {
    printf("Error: cannot create the IVF file.\n");
    return -1;
  }
  
  /* write header */
  if(krx_ivf_write_header(k) < 0) {
    return -2;
  }
  
  return 0;
}

int krx_ivf_write_header(krx_ivf_t* k) {
  assert(k && k->fp != NULL);

  krx_ivf_write_u8(k, 'D');
  krx_ivf_write_u8(k, 'K');
  krx_ivf_write_u8(k, 'I');
  krx_ivf_write_u8(k, 'F');

  krx_ivf_write_u16(k, k->version);        /* version */
  krx_ivf_write_u16(k, 32);                /* header size */
  krx_ivf_write_u32(k, 0x30385056);        /* four cc */
  krx_ivf_write_u16(k, k->width);          /* width */
  krx_ivf_write_u16(k, k->height);         /* height */
  krx_ivf_write_u32(k, k->timebase_den);   /* rate */
  krx_ivf_write_u32(k, k->timebase_num);   /* scale */
  krx_ivf_write_u64(k, k->num_frames);     /* frame count */
  //krx_ivf_write_u64(k, 0);               /* unused */

  fflush(k->fp);
    
  return 0;
}

int krx_ivf_write_frame(krx_ivf_t* k, uint64_t timestamp, uint8_t* data, uint32_t len) {
  assert(k);
  assert(k->fp != NULL);

  printf("krx_ivf_write_frame, timestamp: %lld, nbytes: %u\n", timestamp, len);

  krx_ivf_write_u32(k, len);          /* bytes in frame */
  krx_ivf_write_u64(k, timestamp);    /* timestamp */
  krx_ivf_write(k, data, len);        /* the frame */

  fflush(k->fp);

  k->num_frames++;

  return 0;
}

int krx_ivf_destroy(krx_ivf_t* k) {
  assert(k);
  assert(k->fp != NULL);
  
  /* rewrite the number of frames */
  fseek(k->fp, 24, SEEK_SET);
  krx_ivf_write_u64(k, k->num_frames);

  if(fclose(k->fp) != 0) {
    printf("Error: cannot close the ivf file.\n");
    return -1;
  }

  k->fp = NULL;
  return 0;
}


int krx_ivf_write_u8(krx_ivf_t* k, uint8_t data) {
  assert(k && k->fp != NULL);

  size_t r = fwrite((char*)&data, 1, 1, k->fp);
  if(r != 1) {
    return -1;
  }

  return 0;
}

int krx_ivf_write_u16(krx_ivf_t* k, uint16_t data) {
  uint8_t* p = (uint8_t*)&data;
  krx_ivf_write_u8(k, p[0]);
  krx_ivf_write_u8(k, p[1]);
  // @todo(roxlu): return valid result
  return 0;
}

int krx_ivf_write_u32(krx_ivf_t* k, uint32_t data) {
  uint8_t* p = (uint8_t*)&data;
  krx_ivf_write_u8(k, p[0]);
  krx_ivf_write_u8(k, p[1]);
  krx_ivf_write_u8(k, p[2]);
  krx_ivf_write_u8(k, p[3]);
  return 0; // @todo(roxlu): return valid result
}

int krx_ivf_write_u64(krx_ivf_t* k, uint64_t data) {
  uint8_t* p = (uint8_t*)&data;
  krx_ivf_write_u8(k, p[0]);
  krx_ivf_write_u8(k, p[1]);
  krx_ivf_write_u8(k, p[2]);
  krx_ivf_write_u8(k, p[3]);
  krx_ivf_write_u8(k, p[4]);
  krx_ivf_write_u8(k, p[5]);
  krx_ivf_write_u8(k, p[6]);
  krx_ivf_write_u8(k, p[7]);
  return 0; // @todo(roxlu): return valid result
}

int krx_ivf_write(krx_ivf_t* k, uint8_t* data, uint32_t len) {
  assert(k);
  assert(k->fp != NULL);

  size_t r = fwrite((char*)data, 1, len, k->fp);
  if(r != len) {
    printf("Error: krx_ivf_write() failed: %zu, nbytes: %u.\n", r, len);
    return -1;
  }

  return 0;
}


int krx_ivf_open(krx_ivf_t* k) {

  if(!k) {
    printf("Error: krx_ivf_open(), failed; invalid pointer.\n");
    return -1;
  }

  if(k->fp) {
    printf("Error: krx_ivf_open(), looks like you already opened the file or didn't call init.\n");
    return -2;
  }

  k->fp = fopen("test.ivf", "rb");
  if(!k->fp) {
    printf("Error: krx_ivf_open(), failed to open the file.\n");
    return -3;
  }

  return 0;
}

int krx_ivf_read_header(krx_ivf_t* k) {
  
  if(!k->fp) {
    printf("Error: krx_ivf_read_header(), failed, file not opened.\n");
    return -1;
  }
  
  /* DKIF */
  uint8_t hd = krx_ivf_read_u8(k);
  uint8_t hk = krx_ivf_read_u8(k);
  uint8_t hi = krx_ivf_read_u8(k);
  uint8_t hf = krx_ivf_read_u8(k);
  k->version = krx_ivf_read_u16(k);
  uint16_t header_len = krx_ivf_read_u16(k);
  uint32_t codec = krx_ivf_read_u32(k);
  k->width = krx_ivf_read_u16(k);
  k->height = krx_ivf_read_u16(k);
  k->timebase_den = krx_ivf_read_u32(k);
  k->timebase_num = krx_ivf_read_u32(k);
  k->num_frames = krx_ivf_read_u64(k);

  printf("ivf.file_tag: %C%C%C%C\n", hd, hk, hi, hf);
  printf("ivf.version: %u\n", k->version);
  printf("ivf.header_length: %u\n", header_len);
  printf("ivf.codec: %4X\n", codec);
  printf("ivf.width: %u\n", k->width);
  printf("ivf.height: %u\n", k->height);
  printf("ivf.timebase_den: %u\n", k->timebase_den);
  printf("ivf.timebase_num: %u\n", k->timebase_num);
  printf("ivf.num_frames: %llu\n", k->num_frames);
  return 0;
}


uint8_t krx_ivf_read_u8(krx_ivf_t* k) {
  uint8_t result = 0;
  int r = fread(&result, 1, 1, k->fp);
  if(r != 1) {
    printf("Error: krx_ivf_read_u8() cannot read: %d.\n", r);
  }
  return result;
}

uint16_t krx_ivf_read_u16(krx_ivf_t* k) {
  uint16_t r = 0;
  uint8_t* ptr = (uint8_t*)&r;
  ptr[0] = krx_ivf_read_u8(k);
  ptr[1] = krx_ivf_read_u8(k);
  return r;
}

uint32_t krx_ivf_read_u32(krx_ivf_t* k) {
  uint32_t r = 0;
  uint8_t* ptr = (uint8_t*)&r;
  ptr[0] = krx_ivf_read_u8(k);
  ptr[1] = krx_ivf_read_u8(k);
  ptr[2] = krx_ivf_read_u8(k);
  ptr[3] = krx_ivf_read_u8(k);
  return r;
}

uint64_t krx_ivf_read_u64(krx_ivf_t* k) {
  uint64_t r = 0;
  uint8_t* ptr = (uint8_t*)&r;
  ptr[0] = krx_ivf_read_u8(k);
  ptr[1] = krx_ivf_read_u8(k);
  ptr[2] = krx_ivf_read_u8(k);
  ptr[3] = krx_ivf_read_u8(k);
  ptr[4] = krx_ivf_read_u8(k);
  ptr[5] = krx_ivf_read_u8(k);
  ptr[6] = krx_ivf_read_u8(k);
  ptr[7] = krx_ivf_read_u8(k);
  return r;
}

int krx_ivf_read_frame(krx_ivf_t* k) {
  uint32_t nbytes = krx_ivf_read_u32(k);
  uint64_t timestamp = krx_ivf_read_u64(k);
  printf("ivf.frame, nbytes: %u, timestamp: %lld\n", nbytes, timestamp);
  return 0;
}
