#include "krx_sdp.h"

#define KRX_SDP_CHECK_STATUS(status, msg, r)    \
  if(status != PJ_SUCCESS) {                    \
    printf("%s\n", msg);                        \
    return r;                                   \
  }

/* ---------------------------------------------------------------------------- */

static int krx_sdp_parse_candidate(krx_sdp_candidate* c, char* value, int len);
static int krx_sdp_get_attr(krx_sdp* k, char* out, int nbytes, const char* name);
static int krx_sdp_get_media_attr(krx_sdp* k, krx_sdp_media* m, char* out, int nbytes, const char* name);

/* ---------------------------------------------------------------------------- */

int krx_sdp_init(krx_sdp* k) {

  pj_status_t r; 

  if(!k) {
    printf("Error: invalid arguments.\n");
    return -1;
  }

  /* create pool */
  pj_caching_pool_init(&k->cp, NULL, 512);
  k->pool = pj_pool_create(&k->cp.factory, "krx_sdp", 512, 512, NULL);
  if(!k->pool) {
    printf("Error: krx_sdp_init(), pj_pool_create(), failed.\n");
    return -2;
  }

  k->session = NULL;

  return 0;
}

int krx_sdp_parse(krx_sdp* k, const char* buf, int len) {

  pj_status_t r;

  if(!k) {
    printf("Error: krx_sdp_parse(), invalid argument.\n");
    return -1;
  }

  if(!buf) {
    printf("Error: krx_sdp_parse(), buffer is invalid.\n");
    return -2;
  }

  if(!len) {
    printf("Error: krx_sdp_parse(), zero bytes in buffer.\n");
    return -3;
  }

  r = pjmedia_sdp_parse(k->pool, (char*)buf, len, &k->session);
  KRX_SDP_CHECK_STATUS(r, "Error: pjmedia_sdp_parse() failed.", -4);
  
  return 0;
}

int krx_sdp_get_media(krx_sdp* k, krx_sdp_media mout[], int len, int type) {

  int nfound = 0;

  /* validate input */
  if(!k) { return -1;  }
  if(!len) { return -2; } 
  if(!k->session) { return -3; } ;
  if(k->session->media_count < len) { return -4; }

  for(int i = 0; i < k->session->media_count; ++i) {

    pjmedia_sdp_media* m = k->session->media[i];
    if(!m) {
      return -5;
    }
    
    if(type == KRX_SDP_MEDIA_VIDEO) {
  
      if(pj_strcmp2(&m->desc.media, "video") == 0) {
        mout[nfound].index = i;
        ++nfound;
      }
    }

    if(nfound >= len) {
      break;
    }
  }

  return nfound;
}

/* get the ice-ufrag from the general part of the sdp, returns < 0 on error, else length of ufrag. */
int krx_sdp_get_ufrag(krx_sdp* k, char* out, int nbytes) {
  return krx_sdp_get_attr(k, out, nbytes, "ice-ufrag");
}

/* get the ice-pwd from the general part of the sdp. returns < 0 on error, else length of pwd. */
int krx_sdp_get_pwd(krx_sdp* k, char* outpwd, int nbytes) {
  return krx_sdp_get_attr(k, outpwd, nbytes, "ice-pwd");
}

int krx_sdp_get_media_ufrag(krx_sdp* k, krx_sdp_media* m, char* out, int nbytes) {
  return krx_sdp_get_media_attr(k, m, out, nbytes, "ice-ufrag");
}

int krx_sdp_get_media_pwd(krx_sdp* k, krx_sdp_media* m, char* out, int nbytes) {
  return krx_sdp_get_media_attr(k, m, out, nbytes, "ice-pwd");
}

/* @todo(roxlu): implement krx_sdp_get_candidate() */
int krx_sdp_get_candidates(krx_sdp* k, krx_sdp_candidate* out, int ntotal) {

  /* validate */
  if(!k) { return -1; } 
  if(!out) { return -2; } 
  if(!ntotal) { return -3; }
  if(!k->session) { return -4; } 

  int nfound = 0;

  for(unsigned i = 0; i < k->session->attr_count; ++i) {
    if(pj_strcmp2(&k->session->attr[i]->name, "candidate") == 0) {
      printf("%.*s\n", (int)k->session->attr[i]->name.slen, k->session->attr[i]->name.ptr);
    }
  }

  return nfound;
}

int krx_sdp_get_media_candidates(krx_sdp* k, krx_sdp_media* m, int nmedia, krx_sdp_candidate* out, int nout) {

  /* validate */
  if(!k) { return -1; } 
  if(!m) { return -2; } 
  if(!out) { return -3; } 
  if(!nout) { return -4; } 
  if(!k->session) { return -5; } 
  if(!nmedia) { return -6; } 

  int r = 0;
  int nfound = 0;
  pjmedia_sdp_media* media = k->session->media[m->index];

  if(!media) { return -6;  }

  for(unsigned i = 0; i < media->attr_count; ++i) {
    if(pj_strcmp2(&media->attr[i]->name, "candidate") == 0) {
      krx_sdp_candidate* c = &out[nfound];
      r = krx_sdp_parse_candidate(c, media->attr[i]->value.ptr, media->attr[i]->value.slen);
      
      if(r >= 0) {
        krx_sdp_print_candidate(c);
        nfound++;
        
        if(nfound >= nout) {
          return nfound-1;
        }
      }
    }
  }

  return nfound;
}

/* @todo(roxlu): add case insensitive string compares in krx_sdp_parse_candidate() */
static int krx_sdp_parse_candidate(krx_sdp_candidate* c, char* value, int len) {

  /* Valdidate */
  if(!c) { return -1; }
  if(!value) { return -2; }
  if(!len) { return -3; } 
  
  /* Foundation */
  char* token = strtok(value, " ");
  if(!token) {
    printf("Error: No foundation in candidate.\n");
    return -1;
  }
  if( (strlen(token)+1) > sizeof(c->foundation)) {
    printf("Error: Foundation string to big for candidate.\n");
    return -2;
  }
  memcpy(c->foundation, token, strlen(token)+1);

  /* Component id */
  token = strtok(NULL, " ");
  if(!token) {
    printf("Error: No component ID found in candidate.\n");
    return -3;
  }
  c->component_id = (uint8_t)atoi(token);

  /* Transport  */
  token = strtok(NULL, " ");
  if(!token) {
    printf("Error: no transport found in candidate.\n");
    return -4;
  }
  
  if(strcmp(token, "udp") == 0 || strcmp(token, "UDP") == 0) {
    c->transport_type = KRX_SDP_UDP;
  }
  else if(strcmp(token, "tcp") == 0 || strcmp(token, "TCP") == 0) {
    c->transport_type = KRX_SDP_TCP;
  }
  else {
    printf("Error: cannot find valid transport in candidate.\n");
    return -5;
  }

  /* Priority */
  token = strtok(NULL, " ");
  if(!token) {
    printf("Error: cannot find priority in candidate.\n");
    return -6;
  }
  c->prio = atoi(token);

  /* Host */
  token = strtok(NULL, " ");
  if(!token) {
    printf("Error: cannot find candidate address.\n");
    return -7;
  }

  if(strchr(token, ':')) {
    printf("Error: @todo(roxlu) implement host:port values in candidates.\n");
    exit(1);
  }

  if((strlen(token)+1) > sizeof(c->host)) {
    printf("Error: invalid length for remote ip in candidate.\n");
    return -8;
  }

  memcpy(c->host, token, strlen(token)+1);

  /* Port */
  token = strtok(NULL, " ");
  if(!token) {
    printf("Error: cannot fid port in candidate.\n");
    return -9;
  }
  c->port = atoi(token);

  /* typ */
  token = strtok(NULL, " ");
  if(!token) {
    printf("Error: candidate doesn't contains `typ` flag.\n");
    return -10;
  }
  if(strcmp(token, "typ") != 0) {
    printf("Error: candidate has invalid `typ` flag.\n");
    return -11;
  }

  /* Candidate type */
  token = strtok(NULL, " ");
  if(!token) {
    printf("Error: cannot find candidate type.\n");
    return -12;
  }

  if(strcmp(token, "host") == 0) {
    c->candidate_type = KRX_SDP_HOST;
  }
  else if(strcmp(token, "srflx") == 0) { 
    c->candidate_type = KRX_SDP_SRFLX;
  }
  else if(strcmp(token, "relay") == 0) {
    c->candidate_type = KRX_SDP_RELAY;
  }
  else if(strcmp(token, "prflx") == 0) {
    c->candidate_type = KRX_SDP_PRFLX;
  }
  else {
    printf("Error: unknown candidate type in candidate string.\n");
    return -13;
  }

  return 0;
}

int krx_sdp_print_candidate(krx_sdp_candidate* c) {

  if(!c) {
    return -1;
  }

  printf("Candidate compoment-id; %d, ip: %14.14s, port:%5.5u, type: %15.15s, transport: %s, prio: %u\n", 
         c->component_id,
         c->host, 
         c->port,
         krx_sdp_candidate_type_to_string(c->candidate_type),
         krx_sdp_transport_type_to_string(c->transport_type),
         c->prio
  );

  return 0;
}

int krx_sdp_shutdown(krx_sdp* k) {
  
  if(!k) {
    printf("Error: krx_sdp_shutdown(), invald argument.\n");
    return -1;
  }

  pj_caching_pool_destroy(&k->cp);

  return 0;
}

const char* krx_sdp_candidate_type_to_string(krx_sdp_candidate_type type) { 
  switch(type) {
    KRX_SDP_DEF_CASE(KRX_SDP_HOST);
    KRX_SDP_DEF_CASE(KRX_SDP_SRFLX);
    KRX_SDP_DEF_CASE(KRX_SDP_RELAY);
    KRX_SDP_DEF_CASE(KRX_SDP_PRFLX);
    default: return "Unknown.";
  }
}
const char* krx_sdp_transport_type_to_string(krx_sdp_transport_type type) {
  switch(type) {
    KRX_SDP_DEF_CASE(KRX_SDP_UDP);
    KRX_SDP_DEF_CASE(KRX_SDP_TCP);
    default: return "Unknown.";
  }
}

/* ---------------------------------------------------------------------------- */

static int krx_sdp_get_attr(krx_sdp* k, char* out, int nbytes, const char* name) {

  /* validate */
  if(!k) { return -1; }
  if(!out) { return -2; } 
  if(!nbytes) { return -3; }
  if(!k->session) { return -4; } 

  /* find the attribute in the general part */
  pjmedia_sdp_attr* attr = pjmedia_sdp_attr_find2(k->session->attr_count, k->session->attr, name, NULL);
  if(!attr) { return -5; }
  if(attr->value.slen > nbytes) { return -6;  }

  /* copy result */
  memcpy(out, attr->value.ptr, attr->value.slen);

  return attr->value.slen;
}

static int krx_sdp_get_media_attr(krx_sdp* k, krx_sdp_media* m, char* out, int nbytes, const char* name) {

  /* validate */
  if(!k) { return -1; }
  if(!out) { return -2; } 
  if(!nbytes) { return -3; }
  if(!k->session) { return -4; } 
  if(k->session->media_count < m->index) { return -5; }

  pjmedia_sdp_media* media = k->session->media[m->index];
  if(!media) { return -6;  }

  pjmedia_sdp_attr* attr = pjmedia_sdp_attr_find2(media->attr_count, media->attr, name, NULL);
  if(!attr) { return -7; } 
  if(attr->value.slen > nbytes) { return -8; } 

  memcpy(out, attr->value.ptr, attr->value.slen);
  
  return attr->value.slen;
}
