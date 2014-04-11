#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include "krx_signaling.h"
#include "krx_https.h"

void sighandler(int signum);

krx_sig sig;

int main() {

  printf("\n\nSignaling Server.\n\n");

  signal(SIGINT, sighandler);
  
  if(krx_sig_init(&sig, "./server-cert.pem", "./server-key.pem") < 0) {
    exit(1);
  }

  if(krx_sig_start(&sig, "0.0.0.0", 7777) < 0) {
    exit(1);
  }

  while(1) {
    krx_sig_update(&sig);
  }

  return 0;
}

void sighandler(int signum) {
  printf("Received SIGINT.\n");
  exit(0);
}
