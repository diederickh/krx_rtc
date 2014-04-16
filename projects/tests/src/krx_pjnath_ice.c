#include "krx_ice_pjnath.h"
#include <pjnath/ice_strans.h>

/* --------------------------------------------------------------------------- */

static int krx_ice_worker_thread(void* user); 
static pj_status_t krx_ice_handle_events(krx_ice* k, unsigned int maxms, unsigned int* pcount);
static void krx_ice_on_rx_data(pj_ice_strans* icest, unsigned int compid, void* pkt, pj_size_t size, const pj_sockaddr_t* saddr, unsigned int saddrlen);
static void krx_ice_on_complete(pj_ice_strans* icest, pj_ice_strans_op op, pj_status_t status);
static int krx_ice_candidate_to_string(char* out, int nbytes, pj_ice_sess_cand* cand);
                              
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
  k->max_hosts = 4;
  k->ncomp = 4;
 
  /* initialize the callbacks */
  pj_bzero(&k->ice_cb, sizeof(k->ice_cb));
  k->ice_cb.on_rx_data = krx_ice_on_rx_data;
  k->ice_cb.on_ice_complete = krx_ice_on_complete;

  /* sdp info */
  k->ice_ufrag = NULL;
  k->ice_pwd = NULL;

  return 0;
}

int krx_ice_start(krx_ice* k) {

  pj_status_t r;

  if(!k) { return -1;  }

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

int krx_ice_start_session(krx_ice* k) {

  pj_status_t r;

  if(!k) { return - 1; } 
  if(!k->ice_st) { return -2; } 

  if(pj_ice_strans_has_sess(k->ice_st)) {
    printf("Error: ice already has a session.\n");
    return -3;
  }

  
  r = pj_ice_strans_init_ice(k->ice_st, PJ_ICE_SESS_ROLE_CONTROLLED, NULL, NULL);
  if(r != PJ_SUCCESS) {
    printf("Error: cannot initialize an ice session.\n");
    return -4;
  }

  /* this is where we can create an sdp */
  char sdp_buf[8096] = { 0 } ;
  sprintf(sdp_buf,
          "v=0\n" 
          "o=- 123456789 34234324 IN IP4 localhost\n"    /* - [identifier] [session version] IN IP4 localhost */
          "s=krx_ice\n"                                  /* software */
          "t=0 0\n"                                      /* start, ending time */
          "a=ice-ufrag:%s\n"
          "a=ice-pwd:%s\n"
          ,
          k->ice_ufrag,
          k->ice_pwd
  );

  /* write each component */
  for(int i = 0; i < k->ncomp; ++i) {

    pj_ice_sess_cand cand[PJ_ICE_ST_MAX_CAND] = { 0 } ;
    char ipaddr[PJ_INET6_ADDRSTRLEN] = { 0 } ;

    /* get default candidate for component, note that compoments start numbering from 1, not zero. */
    r = pj_ice_strans_get_def_cand(k->ice_st, 1, &cand[0]);
    if(r != PJ_SUCCESS) {
      printf("Error: cannot retrieve default candidate for component: %d\n", i+1);
      continue;
    }

    if(i == 0) {
      int offset = strlen(sdp_buf);
      sprintf(sdp_buf + offset, 
              "m=video %d RTP/SAVPF 120\n"
              "c=IN IP4 %s\n"
              ,
              (int)pj_sockaddr_get_port(&cand[0].addr),
              pj_sockaddr_print(&cand[0].addr, ipaddr, sizeof(ipaddr), 0)              
      );

      /* print all candidates */
      unsigned num_cands = PJ_ARRAY_SIZE(cand);
      printf("Found number of candidates: %d\n", num_cands);      

      // (ice_st && ice_st->ice && comp_id && comp_id <= ice_st->comp_cnt && count && cand),
      printf("ice: %p\n", k->ice_st);
      r = pj_ice_strans_enum_cands(k->ice_st, i + 1, &num_cands, cand);
      if(r != PJ_SUCCESS) {
        printf("Error: cannot retrieve candidates.\n");
        exit(1);
      }


#if 1

      for(int j = 0; j < num_cands; ++j) {
        int offset = strlen(sdp_buf);
        char* start_addr = sdp_buf + offset;
        krx_ice_candidate_to_string(sdp_buf, sizeof(sdp_buf)-offset, &cand[j]);
        char* end_addr = sdp_buf + strlen(sdp_buf);
        printf("--------\n%s\n--------------\n", sdp_buf);
      }

      offset = strlen(sdp_buf);
      char* start_addr = sdp_buf + offset;
      krx_ice_candidate_to_string(sdp_buf + offset, sizeof(sdp_buf)-offset, &cand[1]);
      char* end_addr = sdp_buf + strlen(sdp_buf);
#endif
    }


  }


  printf("SDP: %s\n", sdp_buf);
          

  r = pj_ice_strans_init_ice(k->ice_st, PJ_ICE_SESS_ROLE_CONTROLLED, NULL, NULL);
  CHECK_PJ_STATUS(r, "Error: cannot init ice session.\n", -4);

  return 0;
}

int krx_ice_set_stun_server(krx_ice* k, char* addr, unsigned int port) {

  if(!k) { return -1;  }

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

  k->ice_ufrag = (char*)malloc(strlen(username) + 1);
  k->ice_pwd = (char*)malloc(strlen(password) + 1);

  memcpy(k->ice_ufrag, username, strlen(username));
  memcpy(k->ice_pwd, password, strlen(password));

  k->ice_ufrag[strlen(username)+1] = '\0';           /* @todo(roxlu) is this a correct way to copy the username to ice? */
  k->ice_pwd[strlen(password)+1] = '\0';             /* @todo(roxlu) is this correct way to copy the username to ice?? */

  return 0;
}

int krx_ice_shutdown(krx_ice* k) {

  if(!k) { return -1; }

  if(k->ice_ufrag) {
    free(k->ice_ufrag);
    k->ice_ufrag = NULL;
  }

  if(k->ice_pwd) {
    free(k->ice_pwd);
    k->ice_pwd = NULL;
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
  printf("----------------- ice complete -------------------------- \n");
  krx_ice* k = (krx_ice*)pj_ice_strans_get_user_data(icest);
  if(!k) {
    printf("Error: complete but no krx_ice* user data found.\n");
    return;
  }

  krx_ice_start_session(k);
}

static int krx_ice_candidate_to_string(char* out, int nbytes, pj_ice_sess_cand* cand) {

  if(!out) { return -1; }
  if(!nbytes) { return 2; } 
  if(!cand) { return -3; } 

  char ipaddr[PJ_INET6_ADDRSTRLEN];
  #if 0
  /* @todo(roxlu): make sure we don't overflow the out buffer in krx_ice_candidate_to_string() */
  sprintf(out,
          "a=candidate:%.*s %u UDP %u %s %u type %s\n",
          (int)cand->foundation.slen, cand->foundation.ptr,            /* foundation */
          (unsigned)cand->comp_id,                                     /* component id */
          cand->prio,                                                  /* priority */
        "address",
        //        pj_sockaddr_print(&cand->addr, ipaddr, sizeof(ipaddr), 0),   /* socket address */
        // (unsigned)pj_sockaddr_get_port(&cand->addr),
          pj_ice_get_cand_type_name(cand->type)
  );
  #endif
          
  return nbytes;
}
