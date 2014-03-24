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

typedef struct {
  /* networking */
  int sock;
  int port;
  struct sockaddr_in saddr;
  unsigned char buf[KRX_UDP_BUF_LEN];
  struct sockaddr_in client;

  /* stun */
  StunAgent agent;
  StunMessage request;
  StunMessage response;
} udp_conn;

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
int handle_stun(udp_conn* c, uint8_t *packet, size_t len); 

int main() {
  printf("udp.\n");

  udp_conn con;
  con.port = 58489;
  con.port = 2233;

  if(krx_udp_init(&con) < 0) {
    exit(EXIT_FAILURE);
  }

  if(krx_udp_bind(&con) < 0) {
    exit(EXIT_FAILURE);
  }

  signal(SIGINT, krx_udp_sighandler);

  while(must_run) {
    printf("..\n");
    krx_udp_receive(&con);
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

  flags = STUN_AGENT_USAGE_IGNORE_CREDENTIALS;

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

  output_size = 0;
  memset(output, 0, sizeof(output));
  stun_agent_init(&agent, attr, STUN_COMPATIBILITY_RFC3489, flags);

  status = stun_agent_validate(&agent, &request, packet, len, NULL, NULL);
  print_stun_validation_status(status);

  StunClass request_class = stun_message_get_class(&request);
  if(request_class == STUN_ERROR) {
    printf("Error: request stun class failed.\n");
    exit(0);
  }
  print_stun_class(request_class);

  StunMethod request_method = stun_message_get_method(&request);
  print_stun_method(request_method);

  ret = stun_agent_init_response(&agent, &response, output, 1024, &request);
  printf("Stun agent_init_response ret: %d\n", ret);

  // --------
  uint32_t magic_cookie = 0;
  StunTransactionId transid;
  stun_message_id(&response, transid);
  magic_cookie = *((uint32_t*)transid);
  socklen_t sock_len = sizeof(c->client);
  StunMessageReturn append_ret = stun_message_append_xor_addr_full(&response, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, 
                                                                   (const struct sockaddr*)&c->client, sock_len,
                                                                   magic_cookie);
  // --------

  output_size = stun_agent_finish_message(&agent, &response, NULL, 0);
  printf("Stun response size: %d\n", (int)output_size);
  
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
  handle_stun(c, c->buf, r);



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
