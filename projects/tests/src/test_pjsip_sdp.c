#include <stdlib.h>
#include <stdio.h>
#include <pjlib.h>
#include <pjlib-util.h>
#include <pjmedia/sdp.h>

static int read_file(const char* path, char* buf, int len); 
static void print_sdp(pjmedia_sdp_session* sdp);

#define CHECK_STATUS(status, msg)  \
  if(status != PJ_SUCCESS) {       \
    printf("%s\n", msg);           \
    return 1;                      \
  }
  

int main() {

  printf("\n\nSDP parsing with PJSIP test\n\n");

  char sdp_text[2048];
  if(read_file("sdp.txt", sdp_text, sizeof(sdp_text)) < 0) {
    exit(1);
  }

  printf("---------------------------- sdp ----------------------\n");
  printf("%s\n\n", sdp_text);
  
  pj_status_t r; 
  pj_caching_pool cp;
  pj_pool_t* pool;
  pjmedia_sdp_session* sdp = NULL;

  r = pj_init();
  CHECK_STATUS(r, "Error: pj_init() failed.\n");

  r = pjlib_util_init();
  CHECK_STATUS(r, "Error: pjlib_util_init() failed.\n");

  pj_caching_pool_init(&cp, NULL, 512);
  
  pool = pj_pool_create(&cp.factory, "parser_test", 512, 512, NULL);
  if(!pool) {
    printf("Error: pj_pool_create(), failed.\n");
    exit(1);
  }

  int len = strlen(sdp_text);
  r = pjmedia_sdp_parse(pool, sdp_text, strlen(sdp_text), &sdp);
  CHECK_STATUS(r, "Error: pjmedia_sdp_parse() failed.");
  
  const pjmedia_sdp_attr* attr;
  pjmedia_sdp_attr* const  media[4]; //  = { 0 };
  pj_str_t str_media = pj_str("media");


  attr = pjmedia_sdp_attr_find2(sdp->attr_count, sdp->attr, "video", NULL);
  if(attr) {
    printf("YES found attr.\n");
  }
  print_sdp(sdp);
  return 0;
};


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

static void print_sdp(pjmedia_sdp_session* sdp) {

  if(!sdp) {
    printf("Error: invalid pjmedia_sdp_session.\n");
    return;
  }

  /* some general info */
  printf("sdp.attr_count: %d\n", sdp->attr_count);
  printf("sdp.media_count: %d\n", sdp->media_count);

  /* loop over found media */
  for(unsigned int i = 0; i < sdp->media_count; ++i) {

    /* get current media */
    pjmedia_sdp_media* m = sdp->media[i];
    if(!m) {
      printf("Error: invalid pjmedia_sdp_media found in pjmedia_sdp_session.\n");
      continue;
    }

#if 0
    if(m->desc.media.slen > 0) {
      printf("---------- found media --------\n");
      printf("media.media: %s\n", m->desc.media.ptr);
      printf("---------- found media --------\n\n");
    }
#endif

    printf("media.desc.port: %d\n", m->desc.port);
    printf("media.desc.port_count: %d\n", m->desc.port_count);
    printf("media.desc.transport: %.*s\n", (int)m->desc.transport.slen, m->desc.transport.ptr );
    printf("media.desc.fmt_count: %d\n", m->desc.fmt_count);
    for(unsigned int i = 0; i < m->desc.fmt_count; ++i) {
      pj_str_t s = m->desc.fmt[i];
      printf("media.desc.fmt (%d): %*.s\n", i, (int)s.slen, s.ptr);
    }

    printf("media.attr_count: %d\n", m->attr_count);
  }
}
