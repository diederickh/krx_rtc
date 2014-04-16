/*
  
  krx_stunc
  --------

  Experimental stun client code; only implements the bare minimum which 
  is needed to setup a webrtc connection between two peers 

  References:
  -----------
  - info on XOR obfuscating which is used with a XOR-MAPPED-ADDRESS: http://blog.malwarebytes.org/intelligence/2013/05/nowhere-to-hide-three-methods-of-xor-obfuscation/
  - javascript stun/turn implemenation: https://github.com/davidrivera/stutter.js

 */
#ifndef KRX_STUNC_H
#define KRX_STUNC_H

/* networking */
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>

/* standard */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "krx_utils.h"

#define STUN_MAGIC_COOKIE 0x2112A442
#define STUN_BIND_REQUEST 0x0001
#define STUN_BIND_RESPONSE 0x0101
#define STUN_MAPPED_ADDRESS 0x0001
#define STUN_XOR_MAPPED_ADDRESS 0x0020

typedef struct krx_stunc krx_stunc;
typedef struct krx_stunc_msg krx_stunc_msg;
typedef struct krx_stunc_attr krx_stunc_attr;
typedef struct krx_stunc_mem krx_stunc_mem;

typedef int(*krx_stunc_send_cb)(krx_stunc* k, uint8_t* data, int nbytes);
//typedef int(*krx_stunc_alloc)

struct krx_stunc_mem {
  uint8_t* buf;
  uint32_t size;
  uint8_t is_free;
  krx_stunc_mem* next;
};

struct krx_stunc {
  
  /* callbacks */
  krx_stunc_send_cb cb_send;
  void* cb_user;
  
  /* incoming data */
  uint8_t buffer[4096];
  uint32_t read_pos;
};

/*
struct krx_stunc_msg {
  uint32_t id[3];
};
*/

struct krx_stunc_attr {
  int type;
  struct sockaddr_in address;
};

krx_stunc* krx_stunc_alloc();
int krx_stunc_start(krx_stunc* s);
int krx_stunc_free(krx_stunc* s);
int krx_stunc_handle_traffic(krx_stunc* s, uint8_t* data, ssize_t nbytes);

#endif
