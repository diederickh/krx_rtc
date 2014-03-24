#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

extern "C" {
#  include <stun5389.h>
}

#define KRX_UDP_BUF_LEN 512

struct udp_conn {
  /* networking */
  int sock;
  int port;
  struct sockaddr_in saddr;
  unsigned char buf[KRX_UDP_BUF_LEN];

  /* stun */
  StunAgent agent;
  StunMessage request;
  StunMessage response;
};

bool must_run = true;
void krx_udp_sighandler(int num);
int krx_udp_init(udp_conn* c);
int krx_udp_bind(udp_conn* c);
int krx_udp_receive(udp_conn* c);
static void print_buffer(uint8_t *buf, size_t len);
void print_stun_validation_status(StunValidationStatus s);
static int handle_stun(uint8_t *packet, size_t len); 

int main() {
  printf("udp.\n");

  udp_conn con;
  con.port = 58489;
  con.port = 2233;

  if(krx_udp_init(&con) < 0) {
    ::exit(EXIT_FAILURE);
  }

  if(krx_udp_bind(&con) < 0) {
    ::exit(EXIT_FAILURE);
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
  ::exit(EXIT_FAILURE);
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

static void print_buffer(uint8_t *buf, size_t len) {
  int i;
  for(int i = 0; i < len; ++i) {
    printf("%02X ", (unsigned char)buf[i]);
    if(i > 0 && i % 40 == 0) {
      printf("\n");
    }
  }
  printf("\n-\n");
}

static int handle_stun(uint8_t *packet, size_t len) {
  StunAgent agent;
  StunValidationStatus status;
  StunMessage request;
  StunMessage response;
  int ret;
  size_t output_size;
  uint8_t output[1024];
  static const uint16_t attr[] = {STUN_ATTRIBUTE_USERNAME, STUN_ATTRIBUTE_MESSAGE_INTEGRITY};
  output_size = 0;
  memset(output, 0, sizeof(output));
  stun_agent_init(&agent, attr, STUN_COMPATIBILITY_RFC3489, STUN_AGENT_USAGE_IGNORE_CREDENTIALS);
  status = stun_agent_validate(&agent, &request, packet, len, NULL, NULL);
  printf("Stun validation status: %d\n", status);
  print_stun_validation_status(status);


  ret = stun_agent_init_response(&agent, &response, output, 1024, &request);
  printf("Stun agent_init_response ret: %d", ret);

  output_size = stun_agent_finish_message(&agent, &response, NULL, 0);
  printf("Stun response size: %d", (int)output_size);

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

  return 0;
}

void print_stun_validation_status(StunValidationStatus s) {
  switch(s) {
    case STUN_VALIDATION_SUCCESS: printf("StunValidationStatus: STUN_VALIDATION_SUCCESS\n"); break;
    case STUN_VALIDATION_NOT_STUN: printf("StunValidationStatus: STUN_VALIDATION_NOT_STUN\n"); break;
    case STUN_VALIDATION_INCOMPLETE_STUN: printf("StunValidationStatus: STUN_VALIDATION_INCOMPLETE_STUN\n"); break;
    case STUN_VALIDATION_BAD_REQUEST: printf("StunValidationStatus: STUN_VALIDATION_BAD_REQUEST\n"); break;
    case STUN_VALIDATION_UNAUTHORIZED_BAD_REQUEST: printf("StunValidationStatus: STUN_VALIDATION_UNAUTHORIZED_BAD_REQUEST\n"); break;
    case STUN_VALIDATION_UNAUTHORIZED: printf("StunValidationStatus: STUN_VALIDATION_UNAUTHORIZED\n"); break;
    case STUN_VALIDATION_UNMATCHED_RESPONSE: printf("StunValidationStatus: STUN_VALIDATION_UNMATCHED_RESPONSE\n"); break;
    case STUN_VALIDATION_UNKNOWN_REQUEST_ATTRIBUTE: printf("StunValidationStatus: STUN_VALIDATION_UNKNOWN_REQUEST_ATTRIBUTE\n"); break;
    case STUN_VALIDATION_UNKNOWN_ATTRIBUTE: printf("StunValidationStatus: STUN_VALIDATION_UNKNOWN_ATTRIBUTE\n"); break;
    default:printf("StunValidationStatus: unknown status.\n"); break;
  }
}
