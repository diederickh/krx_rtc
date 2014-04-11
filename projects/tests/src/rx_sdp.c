#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rx_sdp.h"

/* Static */
/* ------------------------------------------------------------------ */
static char* next(char** buf, const char* sep, const char* strip);
static char* token(char** buf, const char* sep, const char* legal, const char* strip);
static int parse_u32(char** buf, uint32_t* result, uint32_t max);
static int parse_u64(char** buf, uint64_t* result, uint64_t max);

static void parse_origin(rx_sdp* sdp, rx_sdp_origin** result, char* line);
static void parse_connection(rx_sdp* sdp, rx_sdp_connection** result, char* buf);
static void parse_subject(rx_sdp* sdp, char** result, char* buf);
static void parse_information(rx_sdp* sdp, char** result, char* buf);

static void parse_descs(rx_sdp* sdp, char* buf, char* line, rx_sdp_media** result);

/* helpers */
static int strmatch(const char* a, const char* b);            /* case sensitive compare; accepts NULL */
static int strcmpi(const char* a, const char* b);             /* case insensitive string compare; accepts NULL */
static int strncmpi(const char* a, const char* b, size_t n);  /* case insensitive string compare, only n-characters; accepts NULL */

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
  line = next(&buf, CRLF, "");
  if(strmatch(line, "v=0") != 0) {
    printf("Error: invalid SDP, no v=0 found.\n");
    return -4;
  }

  line = next(&buf, CRLF, "");

  for(; line ; line = next(&buf, CRLF, "")) {
    
    if(line[1] != '=') {
      printf("Error: invalid SDP line.\n");
      return -5;
    }

    field = line[0];

    switch(field) {
      case 'o': {
        parse_origin(sdp, &sdp->origin, line);
        break;
      }
      case 's': {
        parse_subject(sdp, &sdp->name, line);
        break;
      }
      case 'i': {
        parse_information(sdp, &sdp->description, line);
        break;
      }
      case 'c': {
        parse_connection(sdp, &sdp->connection, line);
        break;
      }
      case 'm': {
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


/* Static parse functions                                             */
/* ------------------------------------------------------------------ */

/**
 * Parse media descriptors.
 *
 * @param rx_sdp*        [in]    The parser context.
 * @param char*          [in]    The buffer with the sdp
 * @param char*          [in]    The current line that's being parsed in rx_sdp_parse()
 * @param rx_sdp_media** [out]   We allocate a media element and assign it to `*result`
 *
 */
static void parse_descs(rx_sdp* sdp, char* buf, char* line, rx_sdp_media** result) {
}

/**
 * Parse the session information field.
 *
 * i=<session description>
 *
 * @param rx_sdp* [in]  the rx_sdp context
 * @param char**  [out] we'll assign the result to `*result`
 * @param char*   [in]  the line to parse
 */
static void parse_information(rx_sdp* sdp, char** result, char* buf) {
  *result = buf;
}

/**
 * Parse the subject line.
 *
 * s=<session name>
 *
 * @param rx_sdp* [in]  the rx_sdp context
 * @param char**  [out] we'll assign the result to `*result`
 * @param char*   [in]  the line to parse
 *
 */
static void parse_subject(rx_sdp* sdp, char** result, char* line) {
  *result = line;
}

/** 
 * Parse an origin field:
 *
 * o=<username> <session id> <version> <network type> <address type> <address> CRLF
 *
 * @param rx_sdp*         [in]   the rx_sdp context
 * @param rx_sdp_origin** [out]  we'll allocate a new rx_sdp_origin
 * @param char* line      [in]   pointer to the data we will parse
 * 
 * @todo(roxlu): parse_origin in sdp parser needs to set a "ok" or state flag when it fails parsing an origin.
 */
static void parse_origin(rx_sdp* sdp, rx_sdp_origin** result, char* line) {
  
  char* s;
  int r = 0;
  rx_sdp_origin* o = (rx_sdp_origin*)malloc(sizeof(rx_sdp_origin));
  *result = o;

  /* username */
  o->username = token(&line, SPACE TAB, NULL, SPACE TAB);
  if(!o->username) { 
    printf("Error: cannot parse origin, no username.\n");
    free(o);
    o = *result = NULL;
    return;
  }

  /* session id */
  r = parse_u64(&line, &o->session_id, 0);
  if(r != 0) {
    printf("Error: cannot parse origin, session id.\n");
    free(o);
    o = *result = NULL;
    return;
  }

  /* version */
  r = parse_u64(&line, &o->version, 0);
  if(r != 0) {
    printf("Error: cannot parse origin, invalid version.\n");
    free(o);
    o = *result = NULL;
    return;
  }
  
  /* Parse the connection part */
  parse_connection(sdp, &o->address, line);

  /*
  printf("-\n");
  printf("o.username: %s\n", o->username);
  printf("o.session_id: %llu\n", o->session_id);
  printf("o.version: %llu\n", o->version);
  printf("o.adress->address: %s\n", o->address->address);
  printf("-\n");
  */
}

/**
 * Parses a connection string and allocate the result for you. This 
 * parse function is used for the `c=` field, but also in e.g. parse_connection.
 *
 * We parse a connection SDP field:
 * 
 *     c=<network type> <address type> <connection address>
 * 
 * @param rx_sdp*             [in]    The sdp context.
 * @param rx_sdp_connection** [out]   We allocate the rx_sdp_connection for you.
 */
static void parse_connection(rx_sdp* sdp, rx_sdp_connection** result, char* buf) {
  
  char* s = NULL;
  rx_sdp_connection* c = (rx_sdp_connection*)malloc(sizeof(rx_sdp_connection));
  *result = c;

  if(strncmpi(buf, "IN", 2) == 0) {

    /* Network type */
    c->network_type = RX_NET_IN;
    s = token(&buf, SPACE TAB, NULL, NULL);

    /* Address type */
    s = token(&buf, SPACE TAB, NULL, NULL);
    if(strcmpi(s, "IP4") == 0) {
      c->address_type = RX_ADDR_IP4;
    }
    else if(strcmpi(s, "IP6") == 0) {
      c->address_type = RX_ADDR_IP6;
    }
    else {
      printf("Error: invalid address: %s\n", s);
    }

    /* Connection address */
    s = next(&buf, SPACE TAB, SPACE TAB);

    c->address = s;
    if(!s || !*s) {
      printf("Error: invalid address.\n");
      free(c);
      c = *result = NULL;
      return;
    }

    /* ttl and so multi cast */
    s = strchr(s, '/');
    if(s) {
      uint32_t value = 0;
      *s++ = 0;
      if(parse_u32(&s, &value, 256) || (*s && *s != '/')) {
        printf("Error: invalid ttl.\n");
        free(c);
        c = *result = NULL;
        return;
      }

      c->ttl = value;
      c->multi_cast = 1;

      /* multiple groups */
      value = 1;
      if(*s++ == '/') {
        if (parse_u32(&s, &value, 0) || *s) {
          printf("Error: invalid number of multi cast groups.\n");
          free(c);
          c = *result = NULL;
          return;
        }
      }
      c->num_groups = value;
    }
    else {
      c->num_groups = 1;
    }
  }
  else {
    c->network_type = RX_NET_NONE;
    c->address_type = RX_ADDR_NONE;
    c->address = buf;
    c->ttl = 0;
    c->num_groups = 1;
  }
}

/* Static helpers                                                     */
/* ------------------------------------------------------------------ */

/**
 * Read the next line from the SDP buffer until we reach the "sep", which 
 * will probably be the CRLF. We return a pointer to the beginning of the 
 * line. We move the char** towards the next line. We will add the null
 * char at the end of the line.
 *
 * @param char** [in]  The SDP buffer
 * @param char*  [in]  The separator to which we will read.
 * @return char* The line
 * @reutrn NULL  On error.
 */
static char* next(char** buf, const char* sep, const char* strip) {

  char* retval = *buf;
  size_t n = 0;

  if(strip[0]) {
    retval += strspn(retval, strip);
  }

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

/**
 * Read a token in the given `buf` moving the pointer to just after this
 * token (+strip). We move the pointer to which `*buf points to` to after 
 * the read token.
 *
 * @param char**      [in]    The buffer from which you want to get a token.
 * @param const char* [in]    Separator, read this till the token.
 * @param const char* [in]    Valid characters for the token
 * @param const char* [in]    Strip these characters.
 * @return NULL on error
 * @return char* to the next token
 */
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

/**
 * Parse the given `buf` and extract an uint64_t. We move the 
 * pointer to which char* points to just after the number.
 *
 * @param char**    [in]   The buffer to scan for a uint64_t
 * @param uint64_t* [out]  We store the number we find in this variable.
 * @param uint64_t  [in]   Maximum value for result.
 * @return 0 on success
 * @return -1 on error
 */
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

/**
 * Parse the given `buf` and extract an uint32_t. 
 *
 * @param char**    [in]  The buffer to parse. We will read until the number ends.
 * @param uint32_t* [out] We will assign the found value to this parameter.
 * @param uint32_t  [in]  Maximum value that is allowed. 
 * @return -1 on error.
 * @return 0 on success.
 */
static int parse_u32(char** buf, uint32_t* result, uint32_t max) {

  char *ul = *buf;

  ul += strspn(ul, SPACE TAB);

  *result = strtoul(ul, buf, 10);
  if (ul != *buf && !(max && max <= *result)) {
    *buf += strspn(*buf, SPACE TAB);
    return 0;
  }

  return -1;
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

/**
 * Case insensitive compare (only n-characters). Accepts NULL.
 *
 * Example: strncmp("IN ADDR", "IN", 2) -> returns 0
 * 
 * @param const char*  [in]  String to check. 
 * @param const char*  [in]  Check if this string is also in `s1`.
 * @param size_t       [in]  Check this number of characters.
 * @return -1  Negative on error/no match
 * @return 0   We return zero when the string matches.
 */
static int strncmpi(const char* s1, const char* s2, size_t n) {

  if(n == 0) { return -1; }
  if(s1 == s2) {  return -1; }
  if(s1 == NULL || s2 == NULL) { return 0; }

  if(strncmp(s1, s2, n) == 0) {
    return 0; 
  }

  while(n-- > 0) {
    unsigned char a = *s1++, b = *s2++;

    if(a == 0 || b == 0) {
      return (a == b) ? 0 : -1;
    }

    if(a == b) {
      continue;
    }

    if('A' <= a && a <= 'Z') {
      if(a + 'a' - 'A' != b) {
        return -1;
      }
    }
    else if('A' <= b && b <= 'Z') {
      if(a != b + 'a' - 'A') {
        return -1;
      }
    }
    else {
      return -1; 
    }
  }
  return 0;
}
