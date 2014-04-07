#include "krx_global.h"

int krx_global_init() {

  pj_status_t r = pj_init();

  /* initialize pjsip library */
  if(r != PJ_SUCCESS) { 
    printf("Error: krx_sdp_init(), pj_init() failed.\n");
    return -1;
  }

  r = pjlib_util_init();
  if(r != PJ_SUCCESS) {
    printf("Error: krx_sdp_init(), pjlib_util_init() failed.\n");
    return -2;
  }

  /* initialize ssl */
  SSL_library_init();
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();

  return 0;
}

int krx_global_shutdown() {

  ERR_remove_state(0);
  ENGINE_cleanup();
  CONF_modules_unload(1);
  ERR_free_strings();
  EVP_cleanup();
  sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
  CRYPTO_cleanup_all_ex_data();

  return 0;
}
