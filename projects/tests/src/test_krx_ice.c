#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include "krx_sdp.h"
#include "krx_ice.h"

void sighandler(int sn);

krx_ice* ice;

int main() {

  printf("\nkrx_ice\n\n");

  signal(SIGINT, sighandler);

  ice = krx_ice_alloc();
  if(!ice) {
    printf("Error: cannot alloc ice.\n");
    exit(1);
  }

  if(krx_ice_start(ice) < 0) {
    printf("Error: cannot start ice.\n");
    exit(1);
  }

  while(1) {
    krx_ice_update(ice);
  }

  return 0;
}


void sighandler(int sn) {
  printf("\n-sig-\n");
  exit(1);
}
