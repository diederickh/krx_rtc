#include "krx_ice_pjnath.h"

/* --------------------------------------------------------------------------- */

static int krx_ice_worker_thread(void* user); 
static pj_status_t krx_ice_handle_events(krx_ice* k, unsigned int maxms, unsigned int* pcount);
static void krx_ice_on_rx_data(pj_ice_strans* icest, unsigned int compid, void* pkt, pj_size_t size, const pj_sockaddr_t* saddr, unsigned int saddrlen);
static void krx_ice_on_complete(pj_ice_strans* icest, pj_ice_strans_op op, pj_status_t status);
                              
/* --------------------------------------------------------------------------- */

int krx_ice_init(krx_ice* k) {

  pj_status_t r; 

  if(!k) {
    return -1;
  }

  /* initialize pj */
  r = pj_init();
  CHECK_PJ_STATUS(r, "Error: cannot initialize pj.\n", -2);

  r = pjlib_util_init();
  CHECK_PJ_STATUS(r, "Error: cannot initialize pj-util.\n", -3);

  r = pjnath_init();
  CHECK_PJ_STATUS(r, "Error: cannot initialize pjnath.\n", -4);
  
  /* create memory pool */
  pj_caching_pool_init(&k->caching_pool, NULL, 0);
  
  /* initialize the ice settings */
  pj_ice_strans_cfg_default(&k->ice_cfg);

  /* create the pool */
  k->pool = pj_pool_create(&k->caching_pool.factory, "krx_ice_pjnath", 512, 512, NULL); /* 512 = initial size, 512 = incremental size */
  if(!k->pool) {
    printf("Error: cannot create pool.\n");
    return -5;
  }

  k->ice_cfg.stun_cfg.pf = &k->caching_pool.factory;
  
  /* create heap for timers */
  r = pj_timer_heap_create(k->pool, 100, &k->ice_cfg.stun_cfg.timer_heap);
  CHECK_PJ_STATUS(r, "Error: cannot create timer heap.\n", -6);

  /* create ioqueue for network I/O */
  r = pj_ioqueue_create(k->pool, 16, &k->ice_cfg.stun_cfg.ioqueue);
  CHECK_PJ_STATUS(r, "Error: cannot create ioqueue.\n", -7);

  /* create managing thread */
  r = pj_thread_create(k->pool, "krx_ice_pjnath", &krx_ice_worker_thread, k, 0, 0, &k->thread);
  CHECK_PJ_STATUS(r, "Error: cannot create managing thread.", -8);

  k->ice_cfg.af = pj_AF_INET();

  /* @todo(roxlu): we could add a nameserver */

  k->ice_cfg.opt.aggressive = PJ_FALSE; /* @todo(roxlu): read up the aggressive flag in ice_cfg. */
  
  /* default configs */
  k->max_hosts = 2;
  k->ncomp = 2;
 
  /* initialize the callbacks */
  pj_bzero(&k->ice_cb, sizeof(k->ice_cb));
  k->ice_cb.on_rx_data = krx_ice_on_rx_data;
  k->ice_cb.on_ice_complete = krx_ice_on_complete;

  return 0;
}

int krx_ice_start(krx_ice* k) {

  pj_status_t r;

  if(!k) {
    return -1;
  }

  /* use specific stun server? */
  if(k->stun_server_addr.slen) {
    k->ice_cfg.stun.server = k->stun_server_addr;
  }

  if(k->stun_server_port == 0) {
    k->ice_cfg.stun.port = PJ_STUN_PORT;  
  }
  else {
    k->ice_cfg.stun.port = k->stun_server_port;
  }

  /* @todo(roxlu):  add turn features for ice */
  
  /* create the instance */
  r = pj_ice_strans_create("krx_ice_pjnath", 
                           &k->ice_cfg,
                           k->ncomp,
                           k,                /* user data */
                           &k->ice_cb,       /* ice callbacks */
                           &k->ice_st);      /* instance ptr */

  CHECK_PJ_STATUS(r, "Error: cannot create the strans object.\n", -2);

  return 0;
}

int krx_ice_set_stun_server(krx_ice* k, char* addr, unsigned int port) {

  if(!k) {
    return -1;
  }

  if(!addr) {
    printf("Error: invalid stun server ip.\n");
    return -2;
  }

  k->stun_server_addr = pj_str(addr);
  k->stun_server_port = port;
  
  return 0;
}

int krx_ice_set_credentials(krx_ice* k, const char* username, const char* password) {

  if(!k) {
    return -1;
  }

  if(!username) {
    return -2;
  }

  if(!password) {
    return -3;
  }

  return 0;
}

int krx_ice_shutdown(krx_ice* k) {

  if(!k) {
    return -1;
  }

  return 0;
}

/* --------------------------------------------------------------------------- */

static int krx_ice_worker_thread(void* user) {
  krx_ice* k = (krx_ice*)user;

  /* todo(roxlu) - handle stop of thread */
  while(1) {
    krx_ice_handle_events(k, 500, NULL);
  }
  
  return 0;
}

static pj_status_t krx_ice_handle_events(krx_ice* k, unsigned int maxms, unsigned int* pcount) {

  if(!k) {
    printf("Error: krx_ice_handle_events(), invalid krx_ice pointer.\n");
    return PJ_FALSE;
  }

  printf("lets poll: %p.\n", k);
  
  pj_time_val max_timeout = { 0, 0 };
  pj_time_val timeout = { 0, 0 };
  unsigned int count = 0;
  unsigned int net_event_count = 0;
  int c;

  max_timeout.msec = maxms;
  timeout.sec = timeout.msec = 0;

  /* poll the timer to run it and also retrieve earliest entry */
  c = pj_timer_heap_poll(k->ice_cfg.stun_cfg.timer_heap, &timeout);
  if(c > 0) {
    count += c;
  }
  
  /* timer_heap_poll should never return negative values! */
  if(timeout.sec < 0 || timeout.msec < 0) {
    printf("Error: timer returns negative values. Should never happen.\n");
    exit(1);
  }
  
  if(timeout.msec >= 1000) {
    timeout.msec = 999;
  }

  /* use the minimum timeout value */
  if(PJ_TIME_VAL_GT(timeout, max_timeout)) {
    timeout = max_timeout;
  }


  /* poll ioqueue */
  do { 

    c = pj_ioqueue_poll(k->ice_cfg.stun_cfg.ioqueue, &timeout);
    if(c < 0) {
      pj_status_t err = pj_get_netos_error();
      pj_thread_sleep(PJ_TIME_VAL_MSEC(timeout));
      if(pcount) {
        *pcount = count;
        return err;
      }
      else if(c == 0) {
        break;
      }
      else {
        net_event_count += c;
        timeout.sec = timeout.msec = 0;
      }
    }

    
  } while(c > 0 && net_event_count < 1 );

  count += net_event_count;
  if(pcount) {
    *pcount = count;
  }

  return PJ_SUCCESS;
}

static void krx_ice_on_rx_data(pj_ice_strans* icest, 
                               unsigned int compid, void* pkt, pj_size_t size, 
                               const pj_sockaddr_t* saddr, unsigned int saddrlen)
{
  printf("Received a packet.\n");
}

static void krx_ice_on_complete(pj_ice_strans* icest, 
                                    pj_ice_strans_op op, 
                                    pj_status_t status) 
{
  printf("ice complete.\n");
}
