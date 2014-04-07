#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include "krx_ice_pjnath.h"
#include "krx_sdp.h"
#include "krx_global.h"

#define USE_SDP 1
#define USE_ICE 0

// #if USE_SDP && USE_ICE
// #   error Cannot use both SDP and ICE at the same for now. @todo we need to create a global init/shutdown function
// #endif

static int read_file(const char* path, char* buf, int len) ;

void sighandler(int s);

int main() {

  printf("\n\nICE Test\n\n");

  signal(SIGTERM, sighandler);

  if(krx_global_init() < 0) {
    exit(1);
  }

#if USE_SDP
  /* load example SDP */
  krx_sdp sdp;
  char ice_ufrag[512];
  char ice_pwd[512];
  char buf[8192];

  int nbytes = read_file("sdp.txt", buf, sizeof(buf));
  if(nbytes < 0) {
    printf("Error: cannot read file.\n");
    exit(1);
  }

  if(krx_sdp_init(&sdp) < 0) {
    exit(1);
  }

  if(krx_sdp_parse(&sdp, buf, strlen(buf)) < 0) {
    exit(1);
  }
  
  krx_sdp_media sdp_video[1];
  {
    /* get ice-pwd and ice-ufrag. first try to find a media specific one, if that fails get if from the general store */
    if(krx_sdp_get_media(&sdp, sdp_video, 1, KRX_SDP_MEDIA_VIDEO) < 0) {
      exit(1);
    }

    if(krx_sdp_get_media_ufrag(&sdp, sdp_video, ice_ufrag, sizeof(ice_ufrag)) < 0) {
      if(krx_sdp_get_ufrag(&sdp, ice_ufrag, sizeof(ice_ufrag)) < 0) {
        printf("Error: cannot get ice-ufrag.\n");
        exit(1);
      }
    }

    if(krx_sdp_get_media_pwd(&sdp, sdp_video, ice_pwd, sizeof(ice_pwd)) < 0) {
      if(krx_sdp_get_pwd(&sdp, ice_pwd, sizeof(ice_pwd)) < 0) {
        printf("Error: cannot get ice-pwd.\n");
        exit(1);
      }
    }
  }

  /* get candidates, first for video, then from general part if not found */
  krx_sdp_candidate cands[4];
  if(krx_sdp_get_media_candidates(&sdp, sdp_video, 1, cands, 4) <= 0) {
    if(krx_sdp_get_candidates(&sdp, cands, 4) <= 0) {
      printf("Error: cannot find any candidate.\n");
      exit(1);
    }
  }

  if(krx_sdp_shutdown(&sdp) < 0) {
    exit(1);
  };

  printf("ice-ufrag: %s\n", ice_ufrag);
  printf("ice-pwd: %s\n", ice_pwd);
#endif 

#if USE_ICE  
  /* ICE */
  krx_ice ice;

  if(krx_ice_init(&ice) < 0) {
    exit(1);
  }

  if(krx_ice_set_stun_server(&ice, "stun.l.google.com", 19302) < 0) {
    exit(1);
  }

  if(krx_ice_start(&ice) < 0) {
    exit(1);
  }

  while(1) {
  }

#endif

  krx_global_shutdown();

  return 0;
}

void sighandler(int s) {
  printf("Sig called.\n");
  exit(1);
}

static int read_file(const char* path, char* buf, int len) {

  /* try to open the file */
  FILE* fp = fopen(path, "r");
  if(!fp) { 
    printf("Error: cannot read file: %s\n", path);
    return -1;
  }

  /* find size */
  long size = 0;
  fseek(fp, 0, SEEK_END);
  size = ftell(fp);
  fseek(fp, 0, SEEK_SET);

  if(size > len) {
    printf("Error: file size it too large for given buffer. We need: %ld bytes.\n", size);
    fclose(fp);
    return -2;
  }

  size_t r = fread(buf, size, 1, fp);
  if(r != 1) {
    printf("Error: cannot read file into buffer.\n");
    fclose(fp);
    return -3;
  }

  return (int)size;
}

