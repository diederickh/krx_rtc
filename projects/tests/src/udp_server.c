#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <stun5389.h>

#define KRX_UDP_BUF_LEN 512
#define HTTPD_BUF_LEN 4096

/*

  1)  Open index.html in your browser (e.g. start local webserver: 

         cd projects/html
         python -m SimpleHTTPServer
 
  2) Open http://localhost:8000/ in a browser
  3) Execute this application (run ./release from the build dir.) 
  4) Press the START button.
  5) Press the >> button
  
  Repeat 2-5 if you want to test new code.

 */

typedef struct {

  /* initial networking */
  int sock;
  int port;
  struct sockaddr_in saddr;
  unsigned char buf[KRX_UDP_BUF_LEN];
  struct sockaddr_in client;

  /* stun based listening */
  int stun_fd;
  int stun_port;
  struct sockaddr_in stun_saddr;
  struct sockaddr_in stun_raddr;

  /* stun */
  StunAgent agent;
  StunMessage request;
  StunMessage response;
  char stun_pw[512] ;

} udp_conn;

/* accepting http requests for the password from the signaling */
typedef struct {

  /* networking */
  int fd;
  int port;
  struct sockaddr_in saddr;
  unsigned char buf[HTTPD_BUF_LEN];

} httpd_conn;

/* WebRTC */
bool must_run = true;
void krx_udp_sighandler(int num);
int krx_udp_init(udp_conn* c);
int krx_udp_bind(udp_conn* c);
int krx_udp_receive(udp_conn* c);
int krx_udp_send(udp_conn* c, uint8_t* buf, size_t len);

void print_buffer(uint8_t *buf, size_t len);
void print_stun_validation_status(StunValidationStatus s);
void print_stun_class(StunClass c);
void print_stun_method(StunMethod m);
void print_stun_message_return(StunMessageReturn r);
int handle_stun(udp_conn* c, uint8_t *packet, size_t len); 

/* Signaling */
int krx_httpd_init(httpd_conn* c);
void* krx_httpd_thread(void* c); /* c = httpd_conn */
void krx_httpd_receive(void* c);

/* Globals .. */
httpd_conn* hcon_ptr = NULL;
udp_conn* ucon_ptr = NULL;

int main() {
  printf("udp.\n");

  /* WebRTC */
  udp_conn ucon;
  ucon.port = 2233;
  ucon_ptr = &ucon;

  /* HTTP for signaling */
  httpd_conn hcon;
  hcon_ptr = &hcon;
  hcon.port = 3333;
  if(krx_httpd_init(&hcon) < 0) {
    exit(EXIT_FAILURE);
  }

  if(krx_udp_init(&ucon) < 0) {
    exit(EXIT_FAILURE);
  }

  if(krx_udp_bind(&ucon) < 0) {
    exit(EXIT_FAILURE);
  }

  signal(SIGINT, krx_udp_sighandler);

  while(must_run) {
    printf("..\n");
    krx_udp_receive(&ucon);
    sleep(1);
  }

}


void krx_udp_sighandler(int signum) {
  printf("Verbose: handled sig.\n");
  must_run = false;
  exit(EXIT_FAILURE);
}

int krx_udp_init(udp_conn* c) {

  c->sock = socket(AF_INET, SOCK_DGRAM, 0);
  if(c->sock == -1) {
    printf("Error: cannot create socket.\n");
    return -1;
  }

  struct sockaddr_in saddr;
  c->saddr.sin_family = AF_INET;
  c->saddr.sin_addr.s_addr = htonl(INADDR_ANY);
  c->saddr.sin_port = htons(c->port);

  return 1;
}

int krx_udp_bind(udp_conn* c) {
  int r = bind(c->sock, (struct sockaddr*)&c->saddr, sizeof(c->saddr));
  if(r == 0) {
    return 0;
  }

  printf("Error: cannot bind sock.\n");

  return -1;
}

void print_buffer(uint8_t *buf, size_t len) {
  int i;
  for(i = 0; i < len; ++i) {
    printf("%02X ", (unsigned char)buf[i]);
    if(i > 0 && i % 40 == 0) {
      printf("\n");
    }
  }
  printf("\n-\n");
}

int handle_stun(udp_conn* c, uint8_t *packet, size_t len) {

  StunAgent agent;
  StunValidationStatus status;
  StunAgentUsageFlags flags;
  StunMessage request;
  StunMessage response;
  int ret;
  size_t output_size;
  uint8_t output[1024];

  flags = STUN_AGENT_USAGE_IGNORE_CREDENTIALS; //  | STUN_AGENT_USAGE_USE_FINGERPRINT;  

  static const uint16_t attr[] = { 
    STUN_ATTRIBUTE_MAPPED_ADDRESS,
    STUN_ATTRIBUTE_RESPONSE_ADDRESS,
    STUN_ATTRIBUTE_CHANGE_REQUEST,
    STUN_ATTRIBUTE_SOURCE_ADDRESS,
    STUN_ATTRIBUTE_CHANGED_ADDRESS,
    STUN_ATTRIBUTE_USERNAME,
    STUN_ATTRIBUTE_PASSWORD,
    STUN_ATTRIBUTE_MESSAGE_INTEGRITY,
    STUN_ATTRIBUTE_ERROR_CODE,
    STUN_ATTRIBUTE_UNKNOWN_ATTRIBUTES,
    STUN_ATTRIBUTE_REFLECTED_FROM,
    STUN_ATTRIBUTE_CHANNEL_NUMBER,
    STUN_ATTRIBUTE_LIFETIME,
    STUN_ATTRIBUTE_MS_ALTERNATE_SERVER,
    STUN_ATTRIBUTE_MAGIC_COOKIE,
    STUN_ATTRIBUTE_BANDWIDTH,
    STUN_ATTRIBUTE_DESTINATION_ADDRESS,
    STUN_ATTRIBUTE_REMOTE_ADDRESS,
    STUN_ATTRIBUTE_PEER_ADDRESS,
    STUN_ATTRIBUTE_XOR_PEER_ADDRESS,
    STUN_ATTRIBUTE_DATA,
    STUN_ATTRIBUTE_REALM,
    STUN_ATTRIBUTE_NONCE,
    STUN_ATTRIBUTE_RELAY_ADDRESS,
    STUN_ATTRIBUTE_RELAYED_ADDRESS,
    STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS,
    STUN_ATTRIBUTE_REQUESTED_ADDRESS_TYPE,
    STUN_ATTRIBUTE_REQUESTED_PORT_PROPS,
    STUN_ATTRIBUTE_REQUESTED_PROPS,
    STUN_ATTRIBUTE_EVEN_PORT,
    STUN_ATTRIBUTE_REQUESTED_TRANSPORT,
    STUN_ATTRIBUTE_DONT_FRAGMENT,
    STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,
    STUN_ATTRIBUTE_TIMER_VAL,
    STUN_ATTRIBUTE_REQUESTED_IP,
    STUN_ATTRIBUTE_RESERVATION_TOKEN,
    STUN_ATTRIBUTE_CONNECT_STAT,
    STUN_ATTRIBUTE_PRIORITY,
    STUN_ATTRIBUTE_USE_CANDIDATE,
    STUN_ATTRIBUTE_OPTIONS,
    STUN_ATTRIBUTE_MS_VERSION,
    STUN_ATTRIBUTE_SOFTWARE,
    STUN_ATTRIBUTE_ALTERNATE_SERVER,
    STUN_ATTRIBUTE_FINGERPRINT,
    STUN_ATTRIBUTE_ICE_CONTROLLED,
    STUN_ATTRIBUTE_ICE_CONTROLLING,
    STUN_ATTRIBUTE_MS_SEQUENCE_NUMBER,
    STUN_ATTRIBUTE_CANDIDATE_IDENTIFIER
  };

  /* initialize our agent to be compatible with RFC5389 (= with TLS support) */
  output_size = 0;
  memset(output, 0, sizeof(output));
  stun_agent_init(&agent, attr, STUN_COMPATIBILITY_RFC5389, flags);

  /* validate the request */
  status = stun_agent_validate(&agent, &request, packet, len, NULL, NULL);
  print_stun_validation_status(status);

  /* check the class */
  StunClass request_class = stun_message_get_class(&request);
  print_stun_class(request_class);
  if(request_class == STUN_ERROR) {
    printf("Error: request stun class failed.\n");
    exit(0);
  }

  /* what stun method? */
  StunMethod request_method = stun_message_get_method(&request);
  print_stun_method(request_method);

  /* initialize the response */
  ret = stun_agent_init_response(&agent, &response, output, 1024, &request);
  printf("Stun agent_init_response ret: %d\n", ret);

  /* add xor-mapped-address */
  uint32_t magic_cookie = 0;
  uint8_t* cookie_ptr = NULL;
  StunTransactionId transid;
  socklen_t sock_len = 0;
  char client_ip[16] = { 0 } ;
  StunMessageReturn stun_ret = STUN_MESSAGE_RETURN_INVALID;

  stun_message_id(&response, transid);
  magic_cookie = *((uint32_t*)transid);
  sock_len = sizeof(c->client);
  cookie_ptr = (uint8_t*) &magic_cookie;
  inet_ntop(AF_INET, &c->client.sin_addr.s_addr, client_ip, sizeof(client_ip));

  stun_ret = stun_message_append_xor_addr(&response, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, (const struct sockaddr*)&c->client, sock_len);
  print_stun_message_return(stun_ret);

  printf("Received data from: %s\n", client_ip);
  printf("Magic cookie: %02X %02X %02X %02X\n", cookie_ptr[0], cookie_ptr[1], cookie_ptr[2], cookie_ptr[3]);
  
  // username
  // --------
  const char* username = NULL;
  uint16_t username_len = 0;
  username = (const char*)stun_message_find(&request, STUN_ATTRIBUTE_USERNAME, &username_len);
  printf("Username: %s, len: %d\n", username, (int)username_len);

#if 0
  if(username) {
    StunMessageReturn username_res = stun_message_append_bytes(&response, STUN_ATTRIBUTE_USERNAME, username, username_len);
    print_stun_message_return(username_res);

  }
  uint32_t fingerprint = 0;
  if(stun_message_find32(&request, STUN_ATTRIBUTE_FINGERPRINT, &fingerprint) == STUN_MESSAGE_RETURN_SUCCESS) {
    printf("Got fingerprint: %d\n", fingerprint);
    if(stun_message_append32(&response, STUN_ATTRIBUTE_FINGERPRINT, fingerprint) != STUN_MESSAGE_RETURN_SUCCESS) {
      printf("Error while adding the fingerprint.\n");
    }
  }
#endif

  // password
  const char* password = ucon_ptr->stun_pw; // "94ccca06d14fb48c135bdaff30560c4d";
  uint16_t password_len = strlen(password) + 1;
  output_size = stun_agent_finish_message(&agent, &response, (const uint8_t*) password, password_len);

  // answer to the connection
  krx_udp_send(c, output, output_size);

  print_buffer(output, output_size);
  return 0;
}

int krx_udp_receive(udp_conn* c) {

  socklen_t len = sizeof(c->client);
  int r = recvfrom(c->sock, c->buf, KRX_UDP_BUF_LEN, 0, (struct sockaddr*)&c->client, &len);

  if(r < 0) {
    printf("Error: cannot receive.\n");
    return -1;
  }

  printf("Got some data:\n");
  print_buffer(c->buf, r);

  if(r < 2) { 
    printf("Only received 2 bytes?\n");
    return 0;
  }

  if((c->buf[0] == 0x00 || c->buf[0] == 0x01) && (c->buf[1] == 0x00 || c->buf[1] == 0x01) ) {
    handle_stun(c, c->buf, r);
  }
  else {
    printf("No STUN: %02X %02X.\n", c->buf[0], c->buf[1]);
  }

  return 0;
}

int krx_udp_send(udp_conn* c, uint8_t* buf, size_t len) {

  int r = sendto(c->sock, buf, len, 0, (struct sockaddr*)&c->client, sizeof(c->client));
  printf("Sending data on connection: %d\n", r);

  return 0;
}

void print_stun_validation_status(StunValidationStatus s) {
  switch(s) {
    case STUN_VALIDATION_SUCCESS:                   printf("StunValidationStatus: STUN_VALIDATION_SUCCESS\n");                    break;
    case STUN_VALIDATION_NOT_STUN:                  printf("StunValidationStatus: STUN_VALIDATION_NOT_STUN\n");                   break;
    case STUN_VALIDATION_INCOMPLETE_STUN:           printf("StunValidationStatus: STUN_VALIDATION_INCOMPLETE_STUN\n");            break;
    case STUN_VALIDATION_BAD_REQUEST:               printf("StunValidationStatus: STUN_VALIDATION_BAD_REQUEST\n");                break;
    case STUN_VALIDATION_UNAUTHORIZED_BAD_REQUEST:  printf("StunValidationStatus: STUN_VALIDATION_UNAUTHORIZED_BAD_REQUEST\n");   break;
    case STUN_VALIDATION_UNAUTHORIZED:              printf("StunValidationStatus: STUN_VALIDATION_UNAUTHORIZED\n");               break;
    case STUN_VALIDATION_UNMATCHED_RESPONSE:        printf("StunValidationStatus: STUN_VALIDATION_UNMATCHED_RESPONSE\n");         break;
    case STUN_VALIDATION_UNKNOWN_REQUEST_ATTRIBUTE: printf("StunValidationStatus: STUN_VALIDATION_UNKNOWN_REQUEST_ATTRIBUTE\n");  break;
    case STUN_VALIDATION_UNKNOWN_ATTRIBUTE:         printf("StunValidationStatus: STUN_VALIDATION_UNKNOWN_ATTRIBUTE\n");          break;
    default:                                        printf("StunValidationStatus: unknown status.\n");                            break;
  }
}

void print_stun_class(StunClass c) {
  switch(c) { 
    case STUN_REQUEST:     printf("StunClass: STUN_REQUEST.\n");     break;
    case STUN_INDICATION:  printf("StunClass: STUN_INDICATION.\n");  break;
    case STUN_RESPONSE:    printf("StunClass: STUN_RESPONSE.\n");    break;
    case STUN_ERROR:       printf("StunClass: STUN_ERROR.\n");       break;
    default:               printf("StunClass: unknown.\n");          break;
  }
}

void print_stun_method(StunMethod m) {
  switch(m) {
    case STUN_BINDING:            printf("StunMethod: STUN_BINDING.\n");                                       break;
    case STUN_SHARED_SECRET:      printf("StunMethod: STUN_SHARED_SECRET.\n");                                 break;
    case STUN_ALLOCATE:           printf("StunMethod: STUN_ALLOCATE.\n");                                      break;
    case STUN_REFRESH:            printf("StunMethod: STUN_REFRESH or STUN_SET_ACTIVE_DST or STUN_SEND.\n");   break;
    case STUN_CONNECT:            printf("StunMethod: STUN_CONNECT.\n");                                       break;
    case STUN_IND_SEND:           printf("StunMethod: STUN_IND_SEND or STUN_OLD_SET_ACTIVE_DST.\n");           break;
    case STUN_IND_DATA:           printf("StunMethod: STUN_IND_DATA.\n");                                      break;
    case STUN_CREATEPERMISSION:   printf("StunMethod: STUN_CREATEPERMISSION or STUN_IND_CONNECT_STATUS.\n");   break;
    case STUN_CHANNELBIND:        printf("StunMethod: STUN_CHANNELBIND.\n");                                   break;
    default:                      printf("StunMethod: unkown.\n");                                             break;
  }
}

void print_stun_message_return(StunMessageReturn r) {
  switch(r) {
    case STUN_MESSAGE_RETURN_SUCCESS:             printf("StunMessageReturn: STUN_MESSAGE_RETURN_SUCCESS.\n");             break;
    case STUN_MESSAGE_RETURN_NOT_FOUND:           printf("StunMessageReturn: STUN_MESSAGE_RETURN_NOT_FOUND.\n");           break;
    case STUN_MESSAGE_RETURN_INVALID:             printf("StunMessageReturn: STUN_MESSAGE_RETURN_INVALID.\n");             break;
    case STUN_MESSAGE_RETURN_NOT_ENOUGH_SPACE:    printf("StunMessageReturn: STUN_MESSAGE_RETURN_NOT_ENOUGH_SPACE.\n");    break;
    case STUN_MESSAGE_RETURN_UNSUPPORTED_ADDRESS: printf("StunMessageReturn: STUN_MESSAGE_RETURN_UNSUPPORTED_ADDRESS.\n"); break;
    default: printf("StunMessageReturn: unknown.\n"); break;
  }
}

/* HTTP */
/* ----------------------------------------------------------------------------- */
int krx_httpd_init(httpd_conn* c) {

  c->fd = socket(AF_INET, SOCK_STREAM, 0);
  if(c->fd < 0) {
    printf("Error: cannot setup httpd listener.\n");
    return -1;
  }

  /* reuse */
  int val = 1;
  int r = 0;
  r = setsockopt(c->fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
  if(r < 0) {
    printf("Error: cannot set REUSEADDR.\n");
    return -2;
  }

  c->saddr.sin_family = AF_INET;
  c->saddr.sin_addr.s_addr = INADDR_ANY;
  c->saddr.sin_port = htons(c->port);

  r = bind(c->fd, (struct sockaddr*)&c->saddr, sizeof(c->saddr));
  if(r < 0) {
    printf("Error: cannot bind the httpd socket.\n");
    return -2;
  }

  printf("Initialize http listener.\n");

  r = listen(c->fd, 5);
  if(r < 0) {
    printf("Error: cannot listen on the httpd socket.\n");
    return -3;
  }

  krx_httpd_receive((void*)c);

  return 0;
}

/*
  Extracts the password get variable that it receives from the index.html (see projects).
  We receive the ice-pwd value that we use in our stun response. 
*/
void krx_httpd_receive(void *c) {

  httpd_conn* con = (httpd_conn*)c;
  printf("httpd, start listening on: %d.\n", con->port);

  bool run = true;

  while(run) {

    /* accept new connection */
    struct sockaddr_in raddr;
    socklen_t raddr_len = sizeof(raddr);
    int fd = accept(con->fd, (struct sockaddr*) &raddr, &raddr_len);
    if(fd < 0) {
      printf("Error: while accepting on httpd.\n");
      exit(EXIT_FAILURE);
    }
    
    int nread = read(fd, con->buf, HTTPD_BUF_LEN);
    unsigned char* b = con->buf;

    for(int i = 0; i < nread; ++i) {

      /* extract the passwd variable: /?passwd=[THE PASSWORD] */
      if(b[i+0] == 'G' && b[i+1] == 'E' && b[i+2] == 'T' && nread > 100) {
        bool must_copy = false;
        int copy_pos = 0;

        for(int j = i; j < nread; ++j) {

          if(b[j] == '=') {
            must_copy = true;
            continue;
          }

          if(must_copy && b[j] == ' ') {
            printf("Got password: '%s'\n", ucon_ptr->stun_pw);
            run = false;
            must_copy = false;

            close(fd);
            fd = -1;
            break;
          }

          if(must_copy) {
            ucon_ptr->stun_pw[copy_pos++] = b[j];
          }
        }
      }
    }
  }

  close(con->fd);

  printf("Closed httpd socket.\n");
}
