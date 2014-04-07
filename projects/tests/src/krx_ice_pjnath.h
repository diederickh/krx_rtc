/*
  krx_ice_pjnath
  ---------------

  Using PJNATH with the pjnath build in transport support.

 */
#ifndef KRX_ICE_PJNATH
#define KRX_ICE_PJNATH

#include <pjlib.h>
#include <pjlib-util.h>
#include <pjnath.h>

#define CHECK_PJ_STATUS(status, msg, err) \
  if(status != PJ_SUCCESS) {              \
    printf("%s", msg);                    \
    return err;                           \
  } 


typedef struct krx_ice krx_ice;

struct krx_ice {

  /* options */
  int max_hosts;          /* how many candidate we are allowed to discover */
  int ncomp;              /* comp count ... @todo(roxlu) figure out the meaning of this */
  
  /* pjnath specific */
  pj_str_t stun_server_addr;
  int stun_server_port;
  pj_caching_pool caching_pool;
  pj_pool_t* pool;
  pj_ice_strans_cfg ice_cfg;
  pj_ice_strans* ice_st;
  pj_ice_strans_cb ice_cb;
  pj_thread_t* thread;
};

int krx_ice_init(krx_ice* k);
int krx_ice_start(krx_ice* k);
int krx_ice_set_stun_server(krx_ice* k, char* addr, unsigned int port);
int krx_ice_set_credentials(krx_ice* k, const char* username, const char* password);
int krx_ice_shutdown(krx_ice* k);

#endif
