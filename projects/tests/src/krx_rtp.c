#include <string.h>
#include "krx_rtp.h"

int krx_rtp_init(krx_rtp_t* k) {
  
  for(int i = 0; i < RTP_NUM_PACKETS; ++i) {
    krx_rtp_vp8_init(&k->vp8_packets[i]);
  }

  if(krx_ivf_init(&k->ivf) < 0) {
    return -1;
  }
  
  k->ivf.width = 640;
  k->ivf.height = 480;
  k->ivf.timebase_den = 30;
  k->ivf.timebase_num = 1;
  k->ivf.num_frames = 0;
  if(krx_ivf_create(&k->ivf) < 0) {
    return -2;
  }

  k->prev_seq = 0;
  k->pos = 0; 
  k->nsize = 0;

  return 0;
}

int krx_rtp_vp8_init(krx_rtp_vp8_t* v) {
  if(!v) {
    return -1;
  }

  v->is_free = 1;
  v->X = 0;
  v->N = 0;
  v->S = 0;
  v->PID = 0;
  v->I = 0;
  v->L = 0;
  v->T = 0;
  v->K = 0;
  v->PictureID = 0;
  v->TL0PICIDX = 0;
  v->M = 0;
  v->P = 0;
  memset(v->buf, 0x00, sizeof(v->buf));

  return 1;
}

krx_rtp_vp8_t* krx_rtp_find_free_vp8_packet(krx_rtp_t* k) {
  for(int i = 0; i < RTP_NUM_PACKETS; ++i) {
    if(k->vp8_packets[i].is_free == 1) {
      return &k->vp8_packets[i];
    }
  }
  return NULL;
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

  krx_rtp_vp8_t* pkt = krx_rtp_find_free_vp8_packet(k);
  if(!pkt) {
    printf("Error: cannot find a free vp8 packet.\n");
    return -4;
  }

  /* RTP Header */
  pkt->version = (buf[0] & 0xC0) >> 6;
  pkt->padding = (buf[0] & 0x20) >> 4;
  pkt->extension = (buf[0] & 0x10) >> 3;
  pkt->csrc_count = (buf[0] & 0x0F);
  len--;
  buf++;
  
  pkt->marker = (buf[0] & 0x80) >> 7;
  pkt->payload_type = (buf[0] & 0x7F);
  len--;
  buf++;
  
  pkt->sequence_number = krx_rtp_read_u16(buf); 
  buf += 2;
  len -=2;

  pkt->timestamp = krx_rtp_read_u32(buf);
  buf += 4;
  len -= 4;

  pkt->ssrc = krx_rtp_read_u32(buf);
  buf += 4;
  len -= 4;

  // @todo(roxlu): handle csrc_count > 0
  if(pkt->csrc_count != 0) {
    printf("Error: we're only handling a simple rtp packet now. none with csrc_count > 0 (got: %d).\n", pkt->csrc_count);
    exit(EXIT_FAILURE);
  }


  /* VP8 */
  int r = krx_rtp_decode_vp8(k, pkt, buf, len);
  if(r < 0) {
    return -5;
  }
  pkt->is_free = 1;

  return len;
}

int krx_rtp_decode_vp8(krx_rtp_t* k, krx_rtp_vp8_t* v, uint8_t* buf, int len) {

  int start_len = len;

  if(len < 6) {
    printf("Error: krx_rtp_decode_vp8(), cannot decode; which should have at least one byte.\n");
    return -1;
  }

  /* Reset */
  v->I = 0;
  v->L = 0;
  v->K = 0;
  v->PictureID = 0;
  v->TL0PICIDX = 0;
  v->is_free = 0;
  v->X = 0;
  v->N = 0;
  v->S = 0;
  v->PID = 0;
  v->I = 0;
  v->L = 0;
  v->K = 0;
  v->M = 0;
  v->P = 0;

  /* VP8-Payload-Descriptor */
  v->X = (buf[0] & 0x80) >> 7;   /* Extended control bits present */
  v->N = (buf[0] & 0x20) >> 5;   /* None reference frame. (if 1, we can discard this frame). */
  v->S = (buf[0] & 0x10) >> 4;   /* Start of VP8 partition */
  v->PID = (buf[0] & 0x07);      /* Partition index */
  buf++;
  len--;

  /*  X: |I|L|T|K| RSV  | (OPTIONAL)  */
  if(v->X == 1) {
    v->I = (buf[0] & 0x80) >> 7;   /* PictureID present */
    v->L = (buf[0] & 0x40) >> 6;   /* TL0PICIDX present */
    v->T = (buf[0] & 0x20) >> 5;   /* TID present */
    v->K = (buf[0] & 0x10) >> 4;   /* KEYIDX present */
    buf++;
    len--;
  }

  /* PictureID is present */
  if(v->X == 1) {
    v->M = 0;
    v->P = 0;
  }  

  if(v->I) {
    if(buf[0] & 0x80) {  /* M, if M == 1, the picture ID takes 16 bits */
      v->PictureID = krx_rtp_read_u16_picture_id(buf);
      buf += 2;
      len -=2;
    }
    else {
      buf++;
      len--;
    }
  }

  if(v->L) {
    buf++;
    len--;
  }

  if(v->T || v->K) {
    buf++;
    len--;
  }

  if(v->S == 1 && v->PID == 0) {
    if((buf[0] & 0x01) == 0) {
      printf("+ We received a keyframe.\n");
      //  exit(0);
    }
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
  if(v->L == 1) {
    printf("Error: krx_rtp_decode_vp8(), not handling TL0PICIDX.\n");
    return -5;
  }

  /* check if sequence number increases correctly */
  if(k->prev_seq != 0 && k->prev_seq != (v->sequence_number-1)) {
    printf("Error: invalid sequence number; missed a packet.\n");
    k->prev_seq = v->sequence_number;
    k->pos = 0;
    return -6;
  }
  k->prev_seq = v->sequence_number;

  /* VP8 Payload Header */
  if(v->S == 1 && v->PID == 0) {

    /* Inverse key frame flag 0 == key frame. */
    v->P = (buf[0] & 0x01);  

    /* Size of the first data partition in bytes */
    uint8_t size0 = (buf[0] & 0xE0) >> 5;
    uint8_t size1 = buf[1];
    uint8_t size2 = buf[2];
    int nbytes = (size0) + (8 * size1) + (2048 * size2);

    /* Version (more like a type of frame): http://tools.ietf.org/html/rfc6386#section-9  */
    uint8_t ver = buf[0] & 0x1C >> 2;  

    uint16_t video_width = 0;
  }

  /* VP8 Payload Header - FIRST PACKET OF FRAME*/
  if(v->S == 1 && v->PID == 0) {
    printf("+ %d: %d, len: %d, N: %d\n", v->PictureID, v->sequence_number, len, v->N);
  }


  
  /* accumulate buffer */
  memcpy(k->buf + k->pos, buf, len);
  k->pos += len;

  /* Last RTP packet? (we should check for missing packets etc... ) */
  if(v->marker == 1) {
    printf("- %d: %d, len: %d, writing: %u bytes, N: %d, S: %d, PID: %d\n", v->PictureID, v->sequence_number, len, k->pos, v->N, v->S, v->PID);

    static uint64_t ts = 0;

    krx_ivf_write_frame(&k->ivf, ts, k->buf, k->pos);
    printf("\n");

    ts++;
    k->pos = 0; /* reset */
  }

  return start_len;
}

uint16_t krx_rtp_read_u16_picture_id(uint8_t* ptr) {
  uint16_t r = 0;
  uint8_t* p = (uint8_t*)&r;
  p[0] = ptr[1];
  p[1] = (p[0] & 0x80);
  return r;
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

/* ------------------------------------------------------------------------------------------ */

static int krx_rtp_vp8_timestamp_sort(const void* a, const void* b) {
  krx_rtp_vp8_t* pa = (krx_rtp_vp8_t*)a;
  krx_rtp_vp8_t* pb = (krx_rtp_vp8_t*)b;
  if(pa->sequence_number < pb->sequence_number) {
    return 1;
  }
  if(pa->sequence_number > pb->sequence_number) {
    return -1;
  }
  return 0;
}

int krx_rtp_reconstruct_frames(krx_rtp_t* k, uint8_t* buf, int len) {

  /* following the RFC, 
     - collect all packets with the same timestamp
     - sort on sequence number
     - check if the frame is valid:
       - no missing sequence numbers
       - first packet has `S==1` and `PID == 0`
       - last packet has `marker=1`
  */

  krx_rtp_vp8_t* pkt_with_timestamp = krx_rtp_find_packet_with_timestamp(k);
  if(!pkt_with_timestamp) {
    printf("-- Verbose: cannot find a vp8 packet with a timestamp.\n");
    return -1;
  }
  printf("Found packet with timestamp: %u\n", pkt_with_timestamp->timestamp);

  /* get all packets with the same timestamp */
  krx_rtp_vp8_t* packets[10] = { 0 } ;
  int n = krx_rtp_find_packets_with_timestamp(k, pkt_with_timestamp->timestamp, packets, 10);
  if(n == 0) {
    // shouldn't happen
    printf("Verbose: no packet found.\n");
    return -2;
  }
#if 0
  if(n != 2) {
    printf("-- Verbose: not enough packets...: %d\n", n);
    return -3;
  }
#endif

  /* check if frame is complete */
  int is_complete = 0;
  for(int i = 0; i < n; ++i) {
    krx_rtp_vp8_t* pkt = packets[i];
    if(pkt->marker == 1) {
      is_complete = 1;
    }
  }

  if(is_complete == 0) {
    printf("----- no.\n");
    return -3;
  }
  /* sort on sequence number */
  qsort(packets, n, sizeof(krx_rtp_vp8_t*), krx_rtp_vp8_timestamp_sort);


  /* check if the frame is valid. */
#if 1
  int is_valid = 1;
  uint16_t prev_seq = 0;

  for(int i = 0; i < n; ++i) {

    /* no missing sequence number? */
    krx_rtp_vp8_t* pkt = packets[i];
    if(prev_seq && (pkt->sequence_number-1) != prev_seq) { /* @todo(roxlu): uint16 overflow here? */
      printf("-- Verbose: invalid sequence numbers.\n");
      is_valid = 0;
      break;
    }

    /* first packet */
    int is_start = (pkt->S != 1) || (pkt->PID != 0);
    if(pkt->N != 0 && i == 0 && is_start == 1) {
      printf("-- Verbose: first packet is not a valid start packet (i: %d, seqnr: %u).\n", i, pkt->sequence_number);
      is_valid = 0;
      break;
    }


    /* last packet should have marker == 1 */
    if(i == (n-1)) {
      if(pkt->marker == 0) {
        printf("-- Verbose: last packet does not have marker bit set (i: %d, seqnr: %u).\n", i, pkt->sequence_number);
        is_valid = 0;
        break;
      }
    }

  }

  if(is_valid == 0) {
    /* invalid packet; make free again. */
    for(int i = 0; i < n; ++i) {
      packets[i]->is_free = 1;
    }
    printf("-- Verbose: not valid?\n");
    return -3;
  }
#endif

  /* reconstruct the frame data */
  int nbytes = 0;
  for(int i = 0; i < n; ++i) {

    krx_rtp_vp8_t* pkt = packets[i];
    if( (nbytes + pkt->nbytes) >= len) {
      printf("Frame is too big for the reconstruction buffer: %d\n", (nbytes + pkt->nbytes));
      break;
    }

    memcpy(buf + nbytes, pkt->buf, pkt->nbytes);
    nbytes += pkt->nbytes;
  }

  /* reset all packets */
  for(int i = 0; i < n; ++i) {
    packets[i]->is_free = 1;
  }

  return nbytes;
}

/* find a rtp vp8 packet with a timestamp */
krx_rtp_vp8_t* krx_rtp_find_packet_with_timestamp(krx_rtp_t* k) {
  for(int i = 0; i < RTP_NUM_PACKETS; ++i) {
    if(k->vp8_packets[i].timestamp != 0) {
      return &k->vp8_packets[i];
    }
  }
  return NULL;
}

int krx_rtp_find_packets_with_timestamp(krx_rtp_t* k, uint32_t timestamp, krx_rtp_vp8_t* result[], int len) {
  int c = 0;
  for(int i = 0; i < RTP_NUM_PACKETS; ++i) {
    if(k->vp8_packets[i].timestamp == timestamp) {
      result[c] = &k->vp8_packets[i];
      ++c;
      if(c >= len) {
        break;
      }
    }
  }
  return c;
}


void krx_rtp_print(krx_rtp_vp8_t* pkt) {

  if(!pkt) {
    return;
  }

  printf("-\n");
  printf("Version: %d\n", pkt->version);
  printf("Padding: %d\n", pkt->padding);
  printf("Extension: %d\n", pkt->extension);
  printf("CSRC count: %d\n", pkt->csrc_count);
  printf("Marker: %d\n", pkt->marker);
  printf("Payload type: %d\n", pkt->payload_type);
  printf("Sequence number: %d\n", pkt->sequence_number);
  printf("Timestamp: %u\n", pkt->timestamp);
  printf("SSRC: %u\n", pkt->ssrc);
  printf("vp8 X-Extended Control: %d\n", pkt->X);
  printf("vp8 N-Non Reference Frame: %d\n", pkt->N);
  printf("vp8 S-Start of VP8 payload: %d\n", pkt->S);
  printf("vp8 PID-Partition Index: %d\n", pkt->PID);
  printf("vp8 I-Picture ID Present: %d\n", pkt->I);
  printf("vp8 L-Pic IDX Present (TL0PICIDX): %d\n", pkt->L);
  printf("vp8 T-TID Present: %d\n", pkt->T);
  printf("vp8 K-Key IDX Present: %d\n", pkt->K);
  printf("vp8 Picture ID: %u\n", pkt->PictureID);

}
