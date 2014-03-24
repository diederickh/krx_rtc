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
int krx_udp_send(udp_conn* c, struct sockaddr_in* client, uint8_t* buf, size_t len);
void print_buffer(uint8_t *buf, size_t len);
void print_stun_validation_status(StunValidationStatus s);
int handle_stun(uint8_t *packet, size_t len); 

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

int handle_stun(uint8_t *packet, size_t len) {

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

  ret = stun_agent_init_response(&agent, &response, output, 1024, &request);
  printf("Stun agent_init_response ret: %d\n", ret);

  output_size = stun_agent_finish_message(&agent, &response, NULL, 0);
  printf("Stun response size: %d\n", (int)output_size);

  print_buffer(output, output_size);

  return 0;
}

int krx_udp_receive(udp_conn* c) {

  struct sockaddr_in client;
  socklen_t len = sizeof(client);
  int r = recvfrom(c->sock, c->buf, KRX_UDP_BUF_LEN, 0, (struct sockaddr*)&client, &len);

  if(r < 0) {
    printf("Error: cannot receive.\n");
    return -1;
  }

  printf("Got some data:\n");
  print_buffer(c->buf, r);
  handle_stun(c->buf, r);

  //krx_udp_send(c, &client, c->buf, r);

  return 0;
}

int krx_udp_send(udp_conn* c, struct sockaddr_in* client, uint8_t* buf, size_t len) {

  /*
  socklen_t len = sizeof(client);
  char buf[] = "message_from_client";
  int r = sendto(c->sock, buf, strlen(buf)+1, 0, (struct sockaddr*)&server, sizeof(server));
  if(r == -1) {
    printf("Error while sending.\n");
    ::exit(EXIT_FAILURE);
  }
  */
  int r = sendto(c->sock, buf, len, 0, (struct sockaddr*)client, sizeof(client));
  printf("r: %d\n", r);

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
