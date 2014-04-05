#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include "krx_https.h"

void sighandler(int signum);
void on_body(krx_https_conn* c, uint8_t* buf, int len);

krx_https sig;

int main() {
  printf("\n\nSignaling Server.\n\n");

  signal(SIGINT, sighandler);

  if(krx_https_init(&sig, "./server-cert.pem", "./server-key.pem") < 0) {
    exit(1);
  }

  sig.on_body = on_body;

  if(krx_https_start(&sig, "0.0.0.0", 7777) < 0) {
    exit(1);
  }

  while(1) {
    krx_https_update(&sig);
  }

  return 0;
}

void sighandler(int signum) {
  printf("Received SIGINT.\n");
  exit(0);
}

void on_body(krx_https_conn* c, uint8_t* buf, int len) {
  printf("received body.\n");
}
