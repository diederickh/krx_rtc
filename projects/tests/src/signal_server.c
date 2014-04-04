#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include "krx_signaling.h"

void sighandler(int signum);

krx_signaling sig;

int main() {
  printf("\n\nSignaling Server.\n\n");

  signal(SIGINT, sighandler);

  if(krx_signaling_init(&sig) < 0) {
    exit(1);
  }

  if(krx_signaling_start(&sig, "0.0.0.0", 7777) < 0) {
    exit(1);
  }

  while(1) {
    krx_signaling_update(&sig);
  }

  return 0;
}

void sighandler(int signum) {
  printf("Received SIGINT.\n");
  exit(0);
}
