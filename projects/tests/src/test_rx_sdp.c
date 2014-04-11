#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "rx_sdp.h"

static int read_file(const char* path, char* buf, int len);

int main() {
  printf("\nrx_sdp\n");

  /* load file */
  char sdp_input[4096] = { 0 } ;
  if(read_file("sdp.txt", sdp_input, sizeof(sdp_input)) < 0) {
    printf("Error: cannot load te sdp.txt file.\n");
    exit(1);
  }

  printf("--------------------------------------------\n");
  printf("%s\n", sdp_input);
  printf("--------------------------------------------\n\n");

  /* parse */
  rx_sdp* sdp = rx_sdp_alloc();
  rx_sdp_parse(sdp, sdp_input, strlen(sdp_input)+1);
  return 0;
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

