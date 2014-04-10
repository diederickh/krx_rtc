#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rx_sdp.h"

/* Static */
/* ------------------------------------------------------------------ */
static char* next(char** buf, const char* sep);
static char* token(char** buf, const char* sep, const char* legal, const char* strip);
static int parse_u64(char** buf, uint64_t* result, uint64_t max);
static void parse_origin(rx_sdp_origin** result, char* line);

/* helpers */
static int strmatch(const char* a, const char* b);  /* case sensitive compare; accepts NULL */
static int strcmpi(const char* a, const char* b);   /* case insensitive string compare, accepts NULL */

/* API */
/* ------------------------------------------------------------------ */

rx_sdp* rx_sdp_alloc() {
  rx_sdp* sdp = (rx_sdp*)malloc(sizeof(rx_sdp));
  return sdp;
}

int rx_sdp_parse(rx_sdp* sdp, char* buf, int size) {
  char* line;
  char field = '\0';

  if(!sdp) { return -1; } 
  if(!buf) { return -2; } 
  if(!size) { return -3; } 
  
  /* check version string; must be first. */
  line = next(&buf, CRLF);
  if(strmatch(line, "v=0") != 0) {
    printf("Error: invalid SDP, no v=0 found.\n");
    return -4;
  }

  line = next(&buf, CRLF);

  for(; line ; line = next(&buf, CRLF)) {
    
    if(line[1] != '=') {
      printf("Error: invalid SDP line.\n");
      return -5;
    }

    field = line[0];

    switch(field) {
      case 'o': {
        parse_origin(&sdp->origin, line);
        break;
      }
      default: {
        printf("Warning: unhandled field: %c\n", field);
        break;
      }
    }
    printf("> %s\n", line);
  }
  
  return 0;
}

static char* next(char** buf, const char* sep) {
  char* retval = *buf;
  size_t n = 0;

  n = strcspn(retval, sep);
  if(n == 0) {
    return NULL;
  }

  if(retval[n]) {
    retval[n++] = '\0';
    n += strspn(retval + n, sep);
  }
  
  *buf = retval + n;
  if(*retval == '\0') {
    return NULL;
  }

  return retval;
}

static char* token(char** buf, const char* sep, const char* legal, const char* strip) {
  size_t n;
  char* retval = *buf;

  if(strip) {
    retval += strspn(retval, strip);
  }

  if(legal) {
    n  = strspn(retval, legal);
  }
  else {
    n = strcspn(retval, sep);
  }

  if(n == 0) {
    return NULL;
  }

  if(retval[n]) {
    retval[n++] = '\0';
    n += strspn(retval + n, sep);
  }

  *buf = retval + n;

  if(*retval == '\0') {
    return NULL;
  }

  return retval;
}

static int parse_u64(char** buf, uint64_t* result, uint64_t max) {

  uint64_t ull;
  char* s = *buf;

  s += strspn(s, SPACE TAB);

  ull = strtoull(s, buf, 10);

  if(s != *buf && !(max && max <= ull)) {
    *result = (uint64_t)ull;
    *buf += strspn(*buf, SPACE TAB);
    return 0;
  }

  return -1;
}


/* Static */
/* ------------------------------------------------------------------ */

/** 
 * Parse an origin field:
 * o=<username> <session id> <version> <network type> <address type> <address> CRLF
 */
static void parse_origin(rx_sdp_origin** result, char* line) {
  
  printf("parse origin: `%s`\n", line);
  char* s;
  int r = 0;
  rx_sdp_origin* o = (rx_sdp_origin*)malloc(sizeof(rx_sdp_origin));
  *result = o;

  /* username */
  o->username = token(&line, SPACE TAB, NULL, SPACE TAB);
  if(!o->username) { 
    printf("Error: cannot parse origin, no username.\n");
    return;
  }

  /* session id */
  r = parse_u64(&line, &o->session_id, 0);
  if(r != 0) {
    printf("Error: cannot parse origin, session id.\n");
    return;
  }

  /* version */
  r = parse_u64(&line, &o->version, 0);
  if(r != 0) {
    printf("Error: cannot parse origin, invalid version.\n");
    return;
  }

  /* network type */
  s = token(&line, SPACE TAB, NULL, SPACE TAB);
  if(strcmpi(s, "IN") == 0) {
    o->network_type = RX_NET_IN;
  }
  else {
    printf("Error: invalid network type: %s\n", s);
    return;
  }

  /* address type */
  s = token(&line, SPACE TAB, NULL, SPACE TAB);
  if(strcmpi(s, "IP4") == 0) {
    o->address_type = RX_ADDR_IP4;
  }
  else if(strcmpi(s, "IP6") == 0) {
    o->address_type = RX_ADDR_IP6;
  }
 else {
   printf("Error: invalid address: %s\n", s);
 }

  printf("-\n");
  printf("o.username: %s\n", o->username);
  printf("o.session_id: %llu\n", o->session_id);
  printf("o.version: %llu\n", o->version);
  printf("-\n");
}

/**
 * Wrapper around strcmp which accepts NULL.
 * @return zero when they match
 * @return < 0 on error.
 */
static int strmatch(const char* a, const char* b) {

  if(a == NULL || b == NULL) {
    return -1;
  }

  if(a == b) {
    return 0;
  }

  return strcmp(a, b);
}

/**
 * Case insensitive compare, accepts NULL.
 *
 * @return 0 when strings match
 * @return < 0 when strings do not match
 */
int strcmpi(char const *s1, char const *s2) {
  if (s1 == s2) {
    return 0;
  }

  if (s1 == NULL || s2 == NULL) {
    return -1;
  }

  for (;;) {
    unsigned char a = *s1++, b = *s2++;

    if (b == 0) {
      return (a == b) ? 0 : 1;
    }

    if (a == b) {
      continue;
    }

    if ('A' <= a && a <= 'Z') {
      if (a + 'a' - 'A' != b) {
        return -1;
      }
    }
    else if ('A' <= b && b <= 'Z') {
      if (a != b + 'a' - 'A') {
        return -1;
      }
    }
    else {
      return -1;
    }
  }
}
