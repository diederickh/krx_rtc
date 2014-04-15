#include "krx_sdp.h"
#include "krx_utils.h"

/* Valid characters used when parsing tokens */
#define SPACE " "
#define TAB   "\011"
#define CRLF  "\015\012"
#define ALPHA "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define DIGIT "0123456789"
#define TOKEN ALPHA DIGIT "-!#$%&'*+.^_`{|}~"
#define PARSE_ERROR(sdp, msg) { printf("Error: %s\n", msg); sdp->has_parse_error = 1; } 

/* STATIC */
/* ------------------------------------------------------------------------ */
static char* read_token(char** data, const char* sep);
static char* read_line(char** data);                                                             /* reads till the next CRLF, moves the pointer of data */
static int read_u32(char** data, uint32_t* result, uint32_t max);                                /* reads the next couple of characters as a uint32_t */
static int read_u64(char** data, uint64_t* result, uint64_t max);                                /* reads the next couple of characters as a uint64_t */
static void parse_line(krx_sdp* sdp, char* line);                                                /* parse the content of the given line and stores the result in sdp */
static void parse_version(krx_sdp* sdp, char* line);                                             /* parse the version line. */
static void parse_origin(krx_sdp* sdp, char* line, krx_sdp_origin** origin);                     /* parse a origin string, we allocate a new krx_sdp_connection */
static void parse_connection(krx_sdp* sdp, char* line, krx_sdp_connection** con);                /* parse a connection string, we allocate a new krx_sdp_connection */
static void parse_attribute(krx_sdp* sdp, char* line, krx_sdp_attribute** attr);                 /* parse an attribute string, we allocate a new krx_sdp_attribute */
static void parse_candidate(krx_sdp* sdp, char* line, krx_sdp_candidate** cand);                 /* parse a candidate string, we allocate a new krx_sdp_candidate */
static void parse_media(krx_sdp* sdp, char* line, krx_sdp_media** media);                        /* parse a media string, we allocate a new krx_sdp_media  */

/* API */
/* ------------------------------------------------------------------------ */
krx_sdp* krx_sdp_alloc() {

  krx_sdp* k = (krx_sdp*)malloc(sizeof(krx_sdp));
  if(!k) {
    printf("Error: cannot allocate krx_sdp.\n");
    return NULL;
  }
  
  /* @todo(roxlu): init members of krx_sdp in alloc. */
  k->media = NULL;
  k->sdp = NULL;
  k->origin = NULL;
  k->attributes = NULL;
  k->has_parse_error = 0;
  k->curr_attr = &k->attributes;
  return k;
}

void krx_sdp_media_dealloc(krx_sdp_media* m) {
  krx_sdp_media* medias = m;
  while(medias) {
    krx_sdp_media* next = medias->next;

    /* cleanup members */
    krx_sdp_attribute_dealloc(medias->attributes);
    krx_sdp_rtpmap_dealloc(medias->rtpmap);
    krx_sdp_candidate_dealloc(medias->candidates);

    /* nicely clean up */
    medias->attributes = NULL;
    medias->rtpmap = NULL;
    medias->candidates = NULL;
    medias->port = 0;
    medias->num_ports = 0;
    medias->proto = SDP_PROTO_NONE;
    medias->type = SDP_MEDIA_TYPE_NONE;
    medias->next = NULL;
    
    free(medias);
    medias = next;
  }
}

void krx_sdp_origin_dealloc(krx_sdp_origin* o) {
  o->username = NULL;
  o->sess_id = 0;
  o->sess_version = 0;
  o->net_type = SDP_NET_NONE;
  o->addr_type = SDP_ADDR_NONE;

  krx_sdp_connection_dealloc(o->address);

  free(o);
}

void krx_sdp_connection_dealloc(krx_sdp_connection* conn) {
  conn->net_type = SDP_NET_NONE;
  conn->addr_type = SDP_ADDR_NONE;
  conn->address = NULL;
  conn->ttl = 0;
  conn->is_multi_cast = 0;
  conn->num_groups = 0;
}

void krx_sdp_candidate_dealloc(krx_sdp_candidate* cand) {
  krx_sdp_candidate* cands = cand;
  while(cands) {
    krx_sdp_candidate* next = cands->next;

    /* nicly cleanup mem */
    cands->foundation = NULL;
    cands->component_id = 0;
    cands->transport = SDP_TRANSPORT_NONE;
    cands->priority = 0;
    cands->addr =  NULL;
    cands->port = 0;
    cands->raddr = NULL;
    cands->rport = 0;
    cands->type = SDP_CANDIDATE_TYPE_NONE;
    cands->next = NULL;

    free(cands);
    cands = next;
  }
}

void krx_sdp_rtpmap_dealloc(krx_sdp_rtpmap* map) {
  krx_sdp_rtpmap* maps = map;
  while(maps) {
    krx_sdp_rtpmap* next = maps->next;
    maps->type = 0;
    maps->next = NULL;
    free(maps);
    maps = next;
  }
}

void krx_sdp_attribute_dealloc(krx_sdp_attribute* attribs) {
  krx_sdp_attribute* attr = attribs;
  while(attr) {
    krx_sdp_attribute* next = attr->next;
    attr->name = NULL;
    attr->value = NULL;
    attr->next = NULL;
    free(attr); 
    attr = next;
  }
}

void krx_sdp_dealloc(krx_sdp* sdp) {

  if(!sdp) { return; } 


  krx_sdp_attribute_dealloc(sdp->attributes);
  krx_sdp_media_dealloc(sdp->media);

  /* free our copy of the sdp string */
  /* @todo(roxlu): why does freeing of krx_sdp.sdp says that the memory isn't allocated? */
  /*
  if(sdp->sdp) {
    free(sdp->sdp);
    sdp->sdp = NULL;
  }
  */

  free(sdp);
  sdp = NULL;
}

krx_sdp_media* krx_sdp_media_alloc() {

  krx_sdp_media* m = (krx_sdp_media*)malloc(sizeof(krx_sdp_media));
  if(!m) {
    printf("Error: cannot alloc krx_sdp_media.\n");
    return NULL;
  }

  /* @todo(roxlu): init member of krx_sdp_media in alloc. */
  m->port = 0;
  m->num_ports = 0;
  m->proto = SDP_PROTO_NONE;
  m->type = SDP_MEDIA_TYPE_NONE;
  m->next = NULL;
  m->rtpmap = NULL;
  m->attributes = NULL;
  m->candidates = NULL;

  return m;
}

krx_sdp_origin* krx_sdp_origin_alloc() {

  krx_sdp_origin* o = (krx_sdp_origin*)malloc(sizeof(krx_sdp_origin));
  if(!o) {
    printf("Error: cannot allocate origin struct.\n");
    return NULL;
  }

  /* @todo(roxlu): init members of krx_sdp_origin in alloc. */
  
  return o;
}

krx_sdp_connection* krx_sdp_connection_alloc() {

  krx_sdp_connection* c = (krx_sdp_connection*)malloc(sizeof(krx_sdp_connection));
  if(!c) {
    printf("Error: cannot allocate krx_sdp_connection.\n");
    return NULL;
  }

  c->net_type = SDP_NET_NONE;
  c->addr_type = SDP_ADDR_NONE;
  c->address = NULL;
  c->ttl = 0;
  c->is_multi_cast = 0;
  c->num_groups = 0;

  return c;
}

krx_sdp_attribute* krx_sdp_attribute_alloc() {

  krx_sdp_attribute* a = (krx_sdp_attribute*)malloc(sizeof(krx_sdp_attribute));
  if(!a) {
    printf("Error: cannot allocate krx_sdp_attribute.\n");
    return NULL;
  }

  a->name = NULL;
  a->value = NULL;
  a->next = NULL;

  return a;
}

krx_sdp_rtpmap* krx_sdp_rtpmap_alloc() {

  krx_sdp_rtpmap* m = (krx_sdp_rtpmap*)malloc(sizeof(krx_sdp_rtpmap));
  if(!m) {
    printf("Error: cannot allocate krx_sdp_rtpmap.\n");
    return NULL;
  }

  /* @todo(roxlu): init members of krx_sdp_rtpmap in alloc. */
  m->next = NULL;
  m->type = 0;

  return m;
}

krx_sdp_candidate* krx_sdp_candidate_alloc() {

  krx_sdp_candidate* c = (krx_sdp_candidate*)malloc(sizeof(krx_sdp_candidate));
  if(!c) {
    printf("Error: cannot allocate krx_sdp_candidate.\n");
    return NULL;
  }

  /* todo(roxlu): init members of krx_sdp_candidate. */

  c->foundation = NULL;
  c->component_id = 0;
  c->transport = SDP_TRANSPORT_NONE;
  c->priority = 0;
  c->addr = NULL;
  c->port = 0;
  c->raddr = NULL;
  c->rport = 0;
  c->type = SDP_CANDIDATE_TYPE_NONE;
  c->next = NULL;

  return c;
}

/* GENERATING */
/* ------------------------------------------------------------------------ */
int krx_sdp_add_media(krx_sdp* sdp, krx_sdp_media* m) {
  if(!sdp) { return -1; } 
  if(!m) { return -2; } 

  krx_sdp_media* media = sdp->media;
  while(media) {
    media = media->next;
  }

  if(media) {
    media->next = m;
  }
  else {
    sdp->media = m;
  }

  return 0;
}

/* PARSING */
/* ------------------------------------------------------------------------ */
int krx_sdp_parse(krx_sdp* k, char* buf, int nbytes) {

  if(!k) { return -1; };
  if(!buf) { return -2; }
  if(!nbytes) { return -3; } 
  if(k->sdp) { return -4; } 
  if(k->media) { return -5; } 
  if(k->attributes) { return -6; } 
  
  if(nbytes > 1024*1024) {
    printf("Error: the sdp seems a bit to large.\n");
    return -5;
  }

  k->sdp = (char*)malloc(nbytes);
  if(!k->sdp) { return -6; } 
  memcpy(k->sdp, buf, nbytes);

  
  char* line = NULL; 
  do { 

    /* get next line. */
    line = read_line(&k->sdp);
    if(!line) {
      break;
    }

    parse_line(k, line);

    if(k->has_parse_error != 0) {
      /* @todo(roxlu): we probably want to free all allocated objects when krx_sdp_parse()ing fails. */
      printf("Error: cannot parse.\n");
      return -1;
    }
    
  } while(line);

  return 0;
}

int krx_sdp_remove_candidates(krx_sdp_media* m) {

  if(!m) { return -1; } 

  krx_sdp_candidate_dealloc(m->candidates);

  m->candidates = NULL;

  return 0;
}

int krx_sdp_print(krx_sdp* sdp, char* buf, int nbytes) {
  if(!sdp) { return -1; } 
  if(!buf) { return -2; } 
  if(!nbytes) { return -3; } 

  /* @todo(roxlu): krx_sdp_print(), calculat the needed size before writing */
  int pos = 0;
  sprintf(buf + pos, "%s", "v=0\r\n");                                                pos = strlen(buf);
  sprintf(buf + pos, "o=krx_rtc %llu 0 IN IP 0.0.0.0\r\n", (uint64_t)time(NULL));     pos = strlen(buf);
  sprintf(buf + pos, "t=0 0\r\n");                                                    pos = strlen(buf);

  /* @todo(roxlu): krx_sdp_print(), let user add an origin field. */
  sprintf(buf + pos, "c=IN IP4 84.105.186.141\r\n");                                  pos = strlen(buf);

  krx_sdp_media* m = sdp->media;
  while(m) {

    /* media */
    pos = strlen(buf);
    krx_sdp_media_to_string(m, buf + pos, nbytes);

    /* attributes of media */
    pos = strlen(buf);
    krx_sdp_attributes_to_string(m->attributes, buf + pos, nbytes);

    /* candidates of media */
    pos = strlen(buf);
    krx_sdp_candidates_to_string(m->candidates, buf + pos, nbytes); 

    m = m->next;
  }

  printf("----\n%s\n----\n", buf);

  return 0;
}

/* e.g. m=video 32291 RTP/SAVPF 100 116 117 */
int krx_sdp_media_to_string(krx_sdp_media* m, char* buf, int nbytes) {

  int pos = 0;

  /* type */
  sprintf(buf, "m=%s ", krx_sdp_media_type_to_string(m->type));
  pos = strlen(buf);

  /* port */
  sprintf(buf + pos, "%u", m->port);
  pos = strlen(buf);

  /* num ports */
  if(m->num_ports) {
    sprintf(buf + pos, "/%u", m->num_ports);
    pos = strlen(buf);
  }

  /* proto */
  sprintf(buf + pos, " %s ", krx_sdp_proto_type_to_string(m->proto));

  /* fmt */
  krx_sdp_rtpmap* maps = m->rtpmap;
  while(maps) {

    pos = strlen(buf);
    sprintf(buf + pos, "%u", maps->type);

    /* add a space .. */
    if(maps->next) {
      pos = strlen(buf);      
      sprintf(buf + pos, " ");
    }

    maps = maps->next;
  }

  pos = strlen(buf);
  sprintf(buf + pos, "\r\n");

  return 0;
}

int krx_sdp_attributes_to_string(krx_sdp_attribute* a, char* buf, int nbytes) {

  int pos = 0;
  krx_sdp_attribute* attr = a;

  while(attr) {

    if(strlen(attr->value)) {
      /* val = value pair. */
      sprintf(buf + pos, "a=%s:%s\r\n", attr->name, attr->value);    
    }
    else {
      /* only a flag */
      sprintf(buf + pos, "a=%s\r\n", attr->name);
    }

    pos = strlen(buf);
    attr = attr->next;
  }
  return 0;
}

/* url: https://tools.ietf.org/html/rfc5245#section-15.1 */
/* e.g. a=candidate:2083896148 1 udp 1845501695 84.105.186.141 32291 typ srflx raddr 192.168.0.194 rport 60607 */
int krx_sdp_candidates_to_string(krx_sdp_candidate* c, char* buf, int nbytes) {

  int pos = 0;
  krx_sdp_candidate* cand = c;

  while(cand) {

    /* default candidate string */
    sprintf(buf + pos, "a=candidate:%s %u %s %llu %s %u typ %s",
            cand->foundation,
            cand->component_id,
            krx_sdp_transport_type_to_string(cand->transport),
            cand->priority,
            cand->addr,
            cand->port,
            krx_sdp_candidate_type_to_string(cand->type)
    );

    /* type */
    if(cand->type == SDP_SRFLX) {
      pos = strlen(buf);
      sprintf(buf + pos, " raddr %s rport %u", 
              cand->raddr,
              cand->rport
      );

      /* @todo(roxlu): krx_sdp_candidates_to_string(), add other host types. */

    }
    
    pos = strlen(buf);
    sprintf(buf + pos, "\r\n");

    pos = strlen(buf);
    cand = cand->next;
  }
  return 0;
}

char* krx_sdp_candidate_type_to_string(krx_sdp_candidate_type type) {
  switch(type) {
    case SDP_HOST: { return "host"; } 
    case SDP_SRFLX: { return "srflx"; } 
    case SDP_PRFLX: { return "prflx"; } 
    case SDP_RELAY: { return "relay"; } 
    case SDP_CANDIDATE_TYPE_NONE: 
    default: {
      return "unknown-canidate-type";
    }
  }
}

char* krx_sdp_media_type_to_string(krx_sdp_media_type type) {
  switch(type) {
    case SDP_VIDEO: { return "video"; } 
    case SDP_AUDIO: { return "audio"; } 
    case SDP_MEDIA_TYPE_NONE: 
    default: { 
      return "unknown-media-type";
    }
  };
}

char* krx_sdp_proto_type_to_string(krx_sdp_proto proto) {
  switch(proto) {
    case SDP_UDP_RTP_SAVPF: { return "RTP/SAVPF"; } 
    case SDP_PROTO_NONE:
    default: {
      return "unknown-proto-type";
    }
  }
}

char* krx_sdp_transport_type_to_string(krx_sdp_transport_type trans) {
  switch(trans) {
    case SDP_UDP: { return "UDP"; } 
    case SDP_TCP: { return "TCP"; } 
    default: {
      return "unknown-transport-type";
    }
  }
}

/* STATIC */
/* ------------------------------------------------------------------------ */

static void parse_line(krx_sdp* sdp, char* line) {

  if(!line) { printf("Error: invalid sdp line.\n"); return;} 
  if(!sdp) { printf("Error: invalid sdp.\n"); return; } 

  char c = line[0];
  char* value = line + 2;

  switch(c) {
    case 'v': { 
      parse_version(sdp, value);
      break;
    }
    case 'o': {
      parse_origin(sdp, value, &sdp->origin);
      break;
    }
    case 'a': {

      krx_sdp_attribute* attr = NULL;
      parse_attribute(sdp, value, &attr);

      if(attr) {

        /* append the attribute to a media attribute list or to the general session attributes */
        krx_sdp_attribute* tail = *sdp->curr_attr;
        if(!tail) {
          *sdp->curr_attr = attr;
        }
        else {
          while(tail) {
            if(!tail->next) {
              break;
            }
            tail = tail->next;
          }
          tail->next = attr; /* append to end */
        }
      }
      break;
    }
    case 'm': {
      krx_sdp_media* media = NULL;
      parse_media(sdp, value, &media);

      if(media) {
        /* make sure that any new found attributes are added to the attributes of the media element. */
        sdp->curr_attr = &media->attributes;

        /* append the media to the end. */
        krx_sdp_media* tail = sdp->media;
        if(!tail) {
          sdp->media = media;
        }
        else {
          while(tail) {
            if(!tail->next) {
              break;
            }
            tail = tail->next;
          }
          tail->next = media;
        }
      }
      break;
    }
    default: { 
      printf("Warning: unhandled sdp: %s\n", line);
      break;
    }
  }
    
}

static void parse_version(krx_sdp* sdp, char* line) {
  sdp->version = line;
}

/* url: http://tools.ietf.org/html/rfc4566#section-5.2 */
/* example: o=Mozilla-SIPUA-29.0 16705 0 IN IP4 0.0.0.0 */
static void parse_origin(krx_sdp* sdp, char* line, krx_sdp_origin** origin) {

  krx_sdp_origin* o = krx_sdp_origin_alloc();
  if(!o) {
    return;
  }
  *origin = o;
  
  /* username */
  o->username = read_token(&line, SPACE);
  if(!o->username) {
    PARSE_ERROR(sdp, "Invalid username.");
    return;
  }

  /* session id */
  if(read_u64(&line, &o->sess_id, 0) < 0) {
    PARSE_ERROR(sdp, "Invalid session id.");
    return;
  }

  /* session version */
  if(read_u64(&line, &o->sess_version, 0) < 0) {
    PARSE_ERROR(sdp, "Invalid session version.");
    return;
  }

  parse_connection(sdp, line, &o->address);
}

static void parse_attribute(krx_sdp* sdp, char* line, krx_sdp_attribute** attr) {
  char* name;
  krx_sdp_attribute* a;
  *attr = NULL;

  /* parse name part. */
  name = read_token(&line, ":");
  if(!name) {
    PARSE_ERROR(sdp, "Invalid attribute name");
    return ;
  }

  /* parse known attributes and append them to the appropriate lists */
  if(krx_stricmp(name, "candidate") == 0) {
    krx_sdp_candidate* cand = NULL;
    parse_candidate(sdp, line, &cand); 

    if(cand) {
      /* append the candidate to the last media */
      krx_sdp_media* media = sdp->media;
      while(media) {
        if(!media->next) {
          break;
        }
        media = media->next;
      }

      /* shouldn't happen */
      if(!media) {
        printf("Error: parsing an candidate but we haven't found a media element.\n");
        exit(1);
      }

      if(!media->candidates) {
        /* first candidate */
        media->candidates = cand;
      }
      else {
        /* append to last one. */
        krx_sdp_candidate* last_cand = media->candidates;
        while(last_cand) {
          if(!last_cand->next) {
            break;
          }
          last_cand = last_cand->next;
        }

        if(!last_cand) {
          /* shouldn't happen */
          printf("Error: cannot find the last candidate.\n");
          exit(1);
        }
        
        /* and set the new one to the end. */
        last_cand->next = cand;
      }
    }
    
    /* @todo(roxlu): append the new candidate to the last media */
  }
  else {

    /* alloc new attrib */
    a = krx_sdp_attribute_alloc();
    if(!a) {
      PARSE_ERROR(sdp, "Cannot allocate new attribute.");
      return;
    }

    a->name = name;
    a->value = line;
    *attr = a;
  }
}

/* url: http://tools.ietf.org/html/rfc5245#section-15.1 */
/* example: a=candidate:1 1 UDP 1694236671 84.105.186.141 9708 typ srflx raddr 192.168.0.194 rport 5179 */
static void parse_candidate(krx_sdp* sdp, char* line, krx_sdp_candidate** cand) {
  printf("Lets parse a candidate.\n");
  char* s;
  krx_sdp_candidate* c = krx_sdp_candidate_alloc();
  if(!c) {
    return;
  }
  
  /* foundation */
  c->foundation = read_token(&line, SPACE TAB);
  if(!c->foundation) {
    PARSE_ERROR(sdp, "Cannot parse the foundation of a candidate.");
    free(c);
    c = NULL;
    return;
  }

  /* component */
  if(read_u32(&line, &c->component_id, 0) < 0) {
    PARSE_ERROR(sdp, "Cannot parse the component ID of a candidate.");
    free(c);
    c = NULL;
    return;
  }

  /* transport */
  s = read_token(&line, SPACE TAB);
  if(!s) {
    PARSE_ERROR(sdp, "Cannot parse the transport of a candidate.");
    free(c);
    c = NULL;
    return;
  }

  if(krx_stricmp(s, "UDP") == 0) {
    c->transport = SDP_UDP;
  }
  else {
    PARSE_ERROR(sdp, "Unhandled transport type in the candidate.");
    free(c);
    c = NULL;
    return;
  }

  /* priority */
  if(read_u64(&line, &c->priority, 0) < 0) {
    PARSE_ERROR(sdp, "Invalid priority in candidate.");
    free(c);
    c = NULL;
    return;
  }

  /* addr */
  c->addr = read_token(&line, SPACE TAB);
  if(!c->addr) {
    PARSE_ERROR(sdp, "Invalid address in candidate.");
    free(c);
    c = NULL;
    return;
  }

  /* port */
  if(read_u32(&line, &c->port, 0) < 0) {
    PARSE_ERROR(sdp, "Invalid address in candidate.");
    free(c);
    c = NULL;
    return;
  }

  s = read_token(&line, SPACE TAB);
  if(!s || krx_strnicmp(s, "typ", 3) != 0) {
    PARSE_ERROR(sdp, "Invalid candidate not typ string found.");
    free(c);
    c = NULL;    
    return;
  }

  s = read_token(&line, SPACE TAB);
  if(!s) {
    PARSE_ERROR(sdp, "Invalid candidate type was not found.");
    free(c);
    c = NULL;    
    return;
  }

  /* host type */
  if(krx_stricmp(s, "host") == 0) {
    c->type = SDP_HOST;
  }
  else if(krx_stricmp(s, "srflx") == 0) {
    c->type = SDP_SRFLX;
  }
  else if(krx_stricmp(s, "prflx") == 0) {
    c->type = SDP_PRFLX;
  }
  else if(krx_stricmp(s, "relay") == 0) {
    c->type = SDP_RELAY;
  }
  else {
    PARSE_ERROR(sdp, "Invalid host type in candidate.");
    free(c);
    c = NULL;    
    return;
  }

  /* Can we stop here? only when it's a SDP_HOST type */
  if(c->type == SDP_HOST) {
    *cand = c;
    return;
  }

  /* raddr */
  s = read_token(&line, SPACE TAB);
  if(!s || krx_stricmp(s, "raddr") != 0) {
    PARSE_ERROR(sdp, "Invalid candidate, not raddr host type in candidate.");
    free(c);
    c = NULL;    
    return;
  }

  /* raddr value */
  c->raddr = read_token(&line, SPACE TAB);
  if(!c->raddr) {
    PARSE_ERROR(sdp, "Invalid candidate, no raddr found.");
    free(c);
    c = NULL;    
    return;    
  }

  /* `rport` */
  s = read_token(&line, SPACE TAB);
  if(!s || krx_stricmp(s, "rport") != 0) {
    PARSE_ERROR(sdp, "Invalid candidate, no rport found.");
    free(c);
    c = NULL;    
    return;    
  }

  /* rport value */
  if(read_u32(&line, &c->rport, 0) < 0) {
    PARSE_ERROR(sdp, "Invalid candidate, no rport found.");
    free(c);
    c = NULL;    
    return;    
  }

  *cand = c;
}

/* url: http://tools.ietf.org/html/rfc4566#section-5.7 */
/* example: IN IP4 224.2.36.42/127/3 */
static void parse_connection(krx_sdp* sdp, char* line, krx_sdp_connection** con) {

  /* allocate a new connection */
  krx_sdp_connection* c = krx_sdp_connection_alloc();
  if(!c) {
    return;
  }
  *con = c;
  
  if(krx_strnicmp(line, "IN", 2) == 0) {
    char *s;

    /* nettype is internet */
    c->net_type = SDP_NET_IN;
    read_token(&line, SPACE TAB); /* read up to the next SPACE and TAB, and skip them */

    /* address type */
    s = read_token(&line, SPACE TAB);
    if(krx_stricmp(s, "IP4")) {
      c->addr_type = SDP_IP4;
    }
    else if(krx_stricmp(s, "IP6")) {
      c->addr_type = SDP_IP6;
    }
    else {
      PARSE_ERROR(sdp, "Invalid address type.");
      free(c);
      *con = NULL;
      return;
    }

    /* address */
    c->address = read_token(&line, SPACE TAB);
    if(!c->address) {
      PARSE_ERROR(sdp, "Invalid address.");
      free(c);
      *con = NULL;
      return;
    }

    /* ttl */
    s = c->address;
    s = strchr(s, '/');
    if(s) { 
      uint32_t value;
      *s++ = 0;
      if(read_u32(&s, &value, 256) < 0|| (*s && *s != '/')) {
        PARSE_ERROR(sdp, "Inavlid TTL.");
        free(c);
        *con = NULL;
        return;
      }
      c->ttl = value;
      c->is_multi_cast = 1;

      /* groups */
      value = 1;
      if(*s++ == '/') {
        if(read_u32(&s, &value, 0) || *s) {
          PARSE_ERROR(sdp, "Invalid groups.");
          free(c); 
          *con = NULL;
          return;
        }
      }
      c->num_groups = value;
    }
  }
  else {
    PARSE_ERROR(sdp, "Invalid net type.");
    free(c);
    *con = NULL;
    return;
  }
}

/* url: http://tools.ietf.org/html/rfc4566#section-5.14 */
/* example: video 49170/2 RTP/AVP 31 */
static void parse_media(krx_sdp* sdp, char* value, krx_sdp_media** media) {

  uint32_t num = 0;
  char* s;

  krx_sdp_media* m = krx_sdp_media_alloc();
  if(!m) {
    return ;
  }

  /* media type */
  s = read_token(&value, SPACE TAB);
  if(!s) {
    PARSE_ERROR(sdp, "Invalid media.");
    free(m);
    m = NULL;
    return;
  }

  if(krx_stricmp(s, "video") == 0) {
    m->type = SDP_VIDEO;
  }
  else if(krx_stricmp(s, "audio") == 0) {
    m->type = SDP_AUDIO;
  }
  else {
    PARSE_ERROR(sdp, "Unhandled media type.");
    free(m);
    m = NULL;
    return;
  }

  /* port */
  if(read_u32(&value, &num, 0) < 0) {
    PARSE_ERROR(sdp, "Invalid port in media");
    free(m);
    m = NULL;
    return;
  }
  m->port = num;

  /* number of ports */
  if(*value == '/') {  
    *value++ = 0;
    if(read_u32(&value, &num, 0) < 0) {
      PARSE_ERROR(sdp, "Invalid number of parts.");
      free(m);
      m = NULL;
      return;
    }
    m->num_ports = num;
  }

  /* proto */
  s = read_token(&value, SPACE TAB);
  if(!s) {
    PARSE_ERROR(sdp, "Invalid proto");
    free(m);
    m = NULL;
    return;
  }
  if(krx_stricmp(s, "RTP/SAVPF") == 0) {
    m->proto = SDP_UDP_RTP_SAVPF;
  }
  else {
    PARSE_ERROR(sdp, "Unhandled proto.");
    free(m);
    m = NULL;
    return;
  }

  /* rtp format list */
  uint32_t fmt = 0;

  while(read_u32(&value, &fmt, 0) == 0) { 

    /* alloc new krx_sdp_rtpmap */
    krx_sdp_rtpmap* rtpmap = krx_sdp_rtpmap_alloc();
    if(!rtpmap) {
      free(m);
      m = NULL;
      return;
    }
    
    rtpmap->type = fmt;

    /* append the rtpmap to the end */
    if(m->rtpmap == NULL) {
      m->rtpmap = rtpmap;
    }
    else {
      krx_sdp_rtpmap* head = m->rtpmap;
      while(head) {
        if(!head->next) {
          break;
        }
        head = head->next;
      }
      head->next = rtpmap;
    }
  };

  *media = m;
}

static int read_u32(char** data, uint32_t* result, uint32_t max) {

  char* u = *data;
  u += strspn(u, SPACE TAB); /* skip any space or tab chars from the start */

  *result = strtoul(u, data, 10);

  if(u != *data && !(max && max <= *result)) { 
    *data += strspn(*data, SPACE TAB); /* skip any space or tabs chars after the number */
    return 0;
  }

  return -1;
}

static int read_u64(char** data, uint64_t* result, uint64_t max) {

  char* u = *data;
  u += strspn(u, SPACE TAB); /* skip any space or tab chars from the start */

  *result = strtoull(u, data, 10);

  if(u != *data && !(max && max <= *result)) { 
    *data += strspn(*data, SPACE TAB); /* skip any space or tabs chars after the number */
    return 0;
  }

  return -1;
}

static char* read_token(char** data, const char* sep) {

  char* result = *data;
  size_t n = 0;

  if(sep) {
    n = strcspn(result, sep);
  }

  if(result[n]) {
    result[n++] = '\0';
  }
  
  *data += n;

  /* did we reach the end of the string? */
  if(*result == '\0') {
    return NULL;
  }

  return result;
}

static char* read_line(char** data) {

  char* l = *data;
  size_t n = strcspn(l, "\r\n");

  if(n == 0) {
    return NULL;
  }
  
  if(l[n]) {
    l[n++] = '\0';
    n += strspn(l + n, "\r\n");
  }

  *data += n;

  if(*l == '\0') {
    return NULL;
  }

  return l;
}
