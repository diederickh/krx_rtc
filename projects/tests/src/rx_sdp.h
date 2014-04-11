#ifndef RX_SDP_H
#define RX_SDP_H

#include <stdint.h>

#define TAB " "
#define SPACE " "
#define CRLF "\r\n"

typedef struct rx_sdp            rx_sdp;
typedef struct rx_sdp_origin     rx_sdp_origin;
typedef struct rx_sdp_connection rx_sdp_connection;
typedef struct rx_sdp_media      rx_sdp_media;
typedef enum rx_sdp_nettype      rx_sdp_nettype;
typedef enum rx_sdp_addrtype     rx_sdp_addrtype;


enum rx_sdp_nettype {            /* Network Type */
  RX_NET_NONE = 0,               /* Unknown Network Type */
  RX_NET_IN,                     /* Internet */
};

enum rx_sdp_addrtype {
  RX_ADDR_NONE = 0,              /* Unknown Address Type */
  RX_ADDR_IP4,                   /* IP4 address */
  RX_ADDR_IP6,                   /* IP6 address */
};

struct rx_sdp_media {

};

struct rx_sdp_connection {       /* c=<network type> <address type> <connection address> */
  rx_sdp_nettype network_type;
  rx_sdp_addrtype address_type;
  char* address;                 /* The IP address, e.g. 0.0.0.0 */
  uint32_t ttl;                  /* Time to life */
  uint8_t multi_cast;            /* 0 = no multicast, 1 = yes multicast */
  uint32_t num_groups;           /* Number of groups */
};

struct rx_sdp_origin {           /* o=<username> <session id> <version> <network type> <address type> <address> CRLF */ 
  char* username;                /* username */
  uint64_t session_id;           /* session id */
  uint64_t version;              /* version */
  rx_sdp_nettype network_type;   /* network type */
  rx_sdp_addrtype address_type;  /* address type */
  rx_sdp_connection* address;    /* the `address` part */
};

struct rx_sdp {
  int version;                    /* v=, version */
  rx_sdp_origin* origin;          /* o=, origin */
  char* name;                     /* s=<session name> */
  char* description;              /* i=<session description> */
  rx_sdp_connection* connection;  /* c=, connection line */
};

rx_sdp* rx_sdp_alloc();
int rx_sdp_parse(rx_sdp* sdp, char* buf, int size);

#endif
