#include "krx_stun.h"

/* STATIC */
/* --------------------------------------------------------------------------- */

int parse_attribute(uint8_t** buf, krx_stunc_attr* attr);
int parse_attr_mapped_address(uint8_t** buf, krx_stunc_attr* attr);

/* API */
/* --------------------------------------------------------------------------- */
krx_stunc* krx_stunc_alloc() {

  krx_stunc* c = (krx_stunc*)malloc(sizeof(krx_stunc));
  if(!c) {
    return NULL;
  }

  c->cb_send = NULL;
  c->cb_user = NULL;
  c->read_pos = 0;

  return c;
}

int krx_stunc_start(krx_stunc* s) { 

  if(!s) { return -1; } 
  if(!s->cb_send) { return -2; } 

  /* bind request */
  uint8_t buf[20];
  uint8_t* ptr = buf;
    
  krx_write_be_u16(&ptr, STUN_BIND_REQUEST);
  krx_write_be_u16(&ptr, 0x0000);
  krx_write_be_u32(&ptr, STUN_MAGIC_COOKIE);
  krx_write_be_u32(&ptr, random());
  krx_write_be_u32(&ptr, random());
  krx_write_be_u32(&ptr, random());

  s->cb_send(s, buf, 20);

  return 0;
}

/* @todo(roxlu): parse incoming stun data */
/* @todo(roxlu): check if cookie is valid in krx_stunc_handle_traffic() */
/* @todo(roxlu): check if first two bits are zero in krx_stunc_handle_traffic() */
int krx_stunc_handle_traffic(krx_stunc* s, uint8_t* data, ssize_t nbytes) {

  uint8_t* read_ptr = NULL;
  uint16_t msg_type = 0;
  uint16_t msg_length = 0;
  uint32_t msg_cookie = 0;
  uint32_t msg_id[3] = { 0 } ;

  if(!s) { return -1; } 
  if(!data) { return -2; } 
  if(!nbytes) { return -3; } 

  int left = sizeof(s->buffer) - s->read_pos;
  if(left <= 0) {
    printf("No bytes left in buffer .. @todo(roxlu): handle buffer in krx_stunc_handle_traffic.\n");
    exit(0);
  }

  read_ptr = s->buffer + s->read_pos;

  memcpy((void*)s->buffer + s->read_pos, data, nbytes);
  s->read_pos += nbytes;
  
  /* not a complete header yet. */
  if(s->read_pos < 20) {
    return nbytes;
  }

  msg_type = krx_read_be_u16(&read_ptr);
  msg_length = krx_read_be_u16(&read_ptr);
  msg_cookie = krx_read_be_u32(&read_ptr);
  msg_id[0] = krx_read_be_u32(&read_ptr);
  msg_id[1] = krx_read_be_u32(&read_ptr);
  msg_id[2] = krx_read_be_u32(&read_ptr);

  uint8_t* cc = (uint8_t*)&msg_cookie;
  switch(msg_type) {
    case STUN_BIND_RESPONSE: {
      printf("- Bind response\n");
      printf("-- Length: %d\n", msg_length);
      printf("-- Cookie: %02X %02X %02X %02X\n", cc[0], cc[1], cc[2], cc[3]);
      printf("-- ID: (%d, %d, %d)\n", msg_id[0], msg_id[1], msg_id[2]); 

      krx_stunc_attr attribute;
      if(parse_attribute(&read_ptr, &attribute) < 0) {
        printf("XXX Error: cannot parse STUN_BIND_RESPONSE.\n");
      }
      else {
        if(attribute.type == STUN_MAPPED_ADDRESS) {
          /* send success back */
          uint8_t send_buf[32];
          uint8_t* send_ptr = send_buf;
    
          /* stun header (20 bytes) */
          krx_write_be_u16(&send_ptr, STUN_BIND_RESPONSE);
          krx_write_be_u16(&send_ptr, 12);
          krx_write_be_u32(&send_ptr, STUN_MAGIC_COOKIE);
          krx_write_be_u32(&send_ptr, msg_id[0]);
          krx_write_be_u32(&send_ptr, msg_id[1]);
          krx_write_be_u32(&send_ptr, msg_id[2]);

          /* mapped address */
          krx_write_be_u16(&send_ptr, STUN_MAPPED_ADDRESS);
          krx_write_be_u16(&send_ptr, 1);
          krx_write_u8(&send_ptr, 0x00);
          krx_write_u8(&send_ptr, (attribute.address.sin_family == AF_INET) ? 0x01 : 0x02);
          krx_write_be_u16(&send_ptr, attribute.address.sin_port);
          krx_write_be_u32(&send_ptr, attribute.address.sin_addr.s_addr);

          s->cb_send(s, send_buf, 32);
        }
      }
      break;
    };
    default: {
      printf("Unhandled STUN message.\n");
      return -1;
    }
  }

  return nbytes;
}

int parse_attribute(uint8_t** buf, krx_stunc_attr* attr) {

  uint16_t attr_type = 0;
  uint16_t attr_length = 0;
  
  attr_type = krx_read_be_u16(buf);
  attr_length = krx_read_be_u16(buf);

  printf("-- Attribute:\n");
  printf("--- Attribute type: %d\n", attr_type);
  printf("--- Attribute length: %d\n", attr_length);

  switch(attr_type) {
    case STUN_MAPPED_ADDRESS: { 
      parse_attr_mapped_address(buf, attr);
      break;
    }
    default: {
      printf("-- Attribute: UNKNOWN\n");
      return -1;
    }
  }

  return 0;
}

int parse_attr_mapped_address(uint8_t** buf, krx_stunc_attr* attr) {

  uint8_t family;
  uint16_t port;
  uint32_t ip;
  unsigned char addr[16];
  
  krx_read_u8(buf); /* padded on 32bit */
  family = krx_read_u8(buf);
  port = krx_read_be_u16(buf);

  if(family != 0x01) {
    /* @todo(roxlu): add IP6 support in parse_attr_mapped_address(). */;
    printf("Error: krx_stunc only handles IP4 for now.\n");
    exit(0);
  }

  if(family == 0x01) {
    ip = krx_read_be_u32(buf);
  }
  else {
    /* @todo - ip6 */
  }

  printf("---- MAPPED-ADDRESS\n");  
  printf("----- Family: %s (%02X)\n", (family == 0x01) ? "IP4" : "IP6", family);
  printf("----- Port: %d\n", port);
  for(int i = 0; i < 4; ++i) {
    addr[i] = (ip >> (i * 8)) & 0xFF;
  }

  printf("----- IP: %d.%d.%d.%d\n", addr[0], addr[1], addr[2], addr[3]);
  attr->type = STUN_MAPPED_ADDRESS;
  attr->address.sin_family = AF_INET;
  attr->address.sin_port = port;
  attr->address.sin_addr.s_addr = ip;

  return 0;
}
