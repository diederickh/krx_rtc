#include "krx_sdp.h"
#include "krx_utils.h"

/* Valid characters used when parsing tokens */
#define SPACE " "
#define TAB   "\011"
#define CRLF  "\015\012"
#define ALPHA "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define DIGIT "0123456789"
#define TOKEN ALPHA DIGIT "-!#$%&'*+.^_`{|}~"

#define PARSE_ERROR(sdp, msg) { printf("Error: %s", msg); sdp->has_parse_error = 1; } 


/* STATIC */
/* ------------------------------------------------------------------------ */
//static char* read_token(char** data, const char* sep, const char* legal, const char* stripleft); /* read a token from the given data, moving the pointer ahead */
static char* read_token(char** data, const char* sep);
static char* read_line(char** data);                                                             /* reads till the next CRLF, moves the pointer of data */
static int read_u32(char** data, uint32_t* result, uint32_t max);                                /* reads the next couple of characters as a uint32_t */
static int read_u64(char** data, uint64_t* result, uint64_t max);                                /* reads the next couple of characters as a uint64_t */
static void parse_line(krx_sdp* sdp, char* line);                                                /* parses the content of the given line and stores the result in sdp */
static void parse_version(krx_sdp* sdp, char* line);                                             /* parse the version line. */
static void parse_origin(krx_sdp* sdp, char* line, krx_sdp_origin** origin);                     /* pase the o= line, we allocate a new krx_sdp_connection */
static void parse_connection(krx_sdp* sdp, char* line, krx_sdp_connection** con);                /* parse a connection string, we allocate a new krx_sdp_connection */

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
  k->has_parse_error = 0;
  return k;
}


void krx_sdp_dealloc(krx_sdp* sdp) {

  if(!sdp) { return; } 

  if(sdp->sdp) {
    free(sdp->sdp);
    sdp->sdp = NULL;
  }

  /* @todo(roxlu): krx_sdp_dealloc(), make sure to free all allocated mem here. */

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
      return;
    }

    /* address */
    c->address = read_token(&line, SPACE TAB);
    if(!c->address) {
      PARSE_ERROR(sdp, "Invalid address.");
      return;
    }

    /* ttl */
    s = c->address;
    s = strchr(s, '/');
    if(s) { 
      uint32_t value;
      *s++ = 0;
      if (read_u32(&s, &value, 256) || (*s && *s != '/')) {
        PARSE_ERROR(sdp, "Inavlid TTL.");
        return;
      }
      c->ttl = value;
      c->is_multi_cast = 1;

      /* groups */
      value = 1;
      if(*s++ == '/') {
        if(read_u32(&s, &value, 0) || *s) {
          PARSE_ERROR(sdp, "Invalid groups.");
        }
      }
      c->num_groups = value;
    }
  }
  else {
    PARSE_ERROR(sdp, "Invalid net type.");
    return;
  }
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
    printf(">> %zu == %s\n", n, result);
  }

  if(result[n]) {
    result[n++] = '\0';
  }
  
  *data += n;
  return result;
}

#if 0
static char* read_token(char** data,                      /* data to read a token from */
                        const char* sep,                  /* read up to this character/separator  */
                        const char* legal,                /* read from the start, when we read one character that is not in `legal` we stop */
                        const char* stripleft             /* remove any of these characters from the start */
) 
{
  size_t n;
  char *retval = *data;

  if (stripleft)
    retval += strspn(retval, stripleft);

  if (legal)
    n = strspn(retval, legal);
  else
    n = strcspn(retval, sep);

  if (n == 0)
    return NULL;

  if (retval[n]) {
    retval[n++] = '\0';
    n += strspn(retval + n, sep);
  }

  *message = retval + n;

  if (*retval == '\0')
    return NULL;

  return retval;

}
#endif

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
