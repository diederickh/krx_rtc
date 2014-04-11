#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#define KRX_UDP_BUF_LEN 512

struct udp_conn {
  int sock;
  int port;
  struct sockaddr_in saddr;
  char buf[KRX_UDP_BUF_LEN];
};

bool must_run = true;
void krx_udp_sighandler(int num);
int krx_udp_init(udp_conn* c);
int krx_udp_bind(udp_conn* c);
int krx_udp_send(udp_conn* c);

int main() {
  printf("udp.\n");

  udp_conn con;
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
    krx_udp_send(&con);
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
  c->saddr.sin_port = 0; /* use random port here */

  return 1;
}

int krx_udp_bind(udp_conn* c) {
  int r = bind(c->sock, (struct sockaddr*)&c->saddr, sizeof(c->saddr));
  if(r == 0) {
    printf("Bind worked!\n");
    return 0;
  }

  printf("Error: cannot bind sock.\n");

  return -1;
}

int krx_udp_send(udp_conn* c) {
  struct sockaddr_in server;
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = htonl(INADDR_ANY);
  server.sin_port = c->port;

  socklen_t len = sizeof(server);
  char buf[] = "message_from_client";
  int r = sendto(c->sock, buf, strlen(buf)+1, 0, (struct sockaddr*)&server, sizeof(server));
  if(r == -1) {
    printf("Error while sending.\n");
    ::exit(EXIT_FAILURE);
  }
  return 0;
}
