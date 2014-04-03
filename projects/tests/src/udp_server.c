
/*

  1)  Open index.html in your browser (e.g. start local webserver) 

         cd projects/html
         python -m SimpleHTTPServer
 
  2) Open http://localhost:8000/ in a browser
  3) Execute this application (run ./release from the build dir.) 
  4) Press the START button.
  5) Press the >> button
  
  Repeat 2-5 if you want to test new code.

  -- 

  Create server/client self-signed certificate/key:

    openssl req -x509 -newkey rsa:2048 -days 3650 -nodes -keyout client-key.pem -out client-cert.pem
    openssl req -x509 -newkey rsa:2048 -days 3650 -nodes -keyout server-key.pem -out server-cert.pem


  References:
  -----------
  - Old version of this file: https://gist.github.com/roxlu/aaef70ee7954e41c8b3e

 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <stun5389.h>

#include <openssl/err.h>
#include <openssl/dh.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/engine.h>

#include "krx_dtls.h"
#include "krx_rtp.h"
#include "krx_ivf.h"
#include <srtp.h>

#define KRX_UDP_BUF_LEN 4096
#define HTTPD_BUF_LEN 4096

/* See RFC 3711 - see strp.h*/
#define KRX_SRTP_MASTER_KEY_LEN 16
#define KRX_SRTP_MASTER_SALT_LEN 14
#define KRX_SRTP_MASTER_LEN (KRX_SRTP_MASTER_KEY_LEN + KRX_SRTP_MASTER_SALT_LEN)

enum {
  KRX_STATE_NONE,
  KRX_STATE_SSL_INIT_READY
};

typedef struct {
  SSL* ssl;
  SSL_CTX* ctx;
  X509* client_cert;
  BIO* in;
  BIO* out;
  bool conn_initialized;
  uint8_t* in_buf;
  int in_pos;
  int in_len;
  uint8_t* out_buf;
  int out_pos;
  int out_len;
  void* user; /* udp_conn */
} krx_ssl;

typedef struct {
  srtp_t session;
  srtp_stream_t stream;
  srtp_policy_t policy;
} krx_srtp;

typedef struct {

  /* general */
  int state; /* just a tiny helper we use for this experimental code to keep track of state */

  /* initial networking */
  int sock;
  int port;
  struct sockaddr_in saddr;
  unsigned char buf[KRX_UDP_BUF_LEN];
  struct sockaddr_in client;

  /* stun based listening */
  int stun_fd;
  int stun_port;
  struct sockaddr_in stun_saddr;
  struct sockaddr_in stun_raddr;

  /* stun */
  StunAgent agent;
  StunMessage request;
  StunMessage response;
  char stun_pw[512] ;

  /* ssl */
  krx_ssl ssl;
  
  /* srtp + rtp */
  krx_srtp srtp;


  krx_dtls_t dtls;
  krx_rtp_t rtp;

} udp_conn;

/* accepting http requests for the password from the signaling */
typedef struct {

  /* networking */
  int fd;
  int port;
  struct sockaddr_in saddr;
  unsigned char buf[HTTPD_BUF_LEN];

} httpd_conn;

/* WebRTC */
bool must_run = true;
void krx_udp_sighandler(int num);
int krx_udp_init(udp_conn* c);
int krx_udp_bind(udp_conn* c);
int krx_udp_receive(udp_conn* c);
int krx_udp_send(udp_conn* c, uint8_t* buf, size_t len);

void print_buffer(uint8_t *buf, size_t len);
void print_stun_validation_status(StunValidationStatus s);
void print_stun_class(StunClass c);
void print_stun_method(StunMethod m);
void print_stun_message_return(StunMessageReturn r);
int handle_stun(udp_conn* c, uint8_t *packet, size_t len); 

/* Signaling */
int krx_httpd_init(httpd_conn* c);
void krx_httpd_receive(httpd_conn* c);

/* SSL<>DTLS */
void krx_ssl_info_callback(const SSL* ssl, int where, int ret);
int krx_ssl_init(krx_ssl* k);
int krx_ssl_conn_init(krx_ssl* k);
int krx_ssl_bio_create(BIO* b);
int krx_ssl_bio_destroy(BIO* b);
int krx_ssl_bio_read(BIO* b, char* buf, int len);
int krx_ssl_bio_write(BIO* b, const char* buf, int len);

long krx_ssl_bio_ctrl(BIO* b, int cmd, long num, void* ptr);
int krx_ssl_verify(int ok, X509_STORE_CTX* ctx);
int krx_ssl_print_fingerprint(krx_ssl* k);
int krx_ssl_encrypt(krx_ssl* k, uint8_t* out, int max, uint8_t* in, int len);
int krx_ssl_decrypt(krx_ssl* k, uint8_t* out, int max, uint8_t* in, int len);

/* SRTP */
int krx_init_srtp(krx_srtp* s);

/* KRX_DTLS (experimental) */
int krx_send_to_browser(krx_dtls_t* k, uint8_t* data, int len);

static struct bio_method_st krx_bio = {
  BIO_TYPE_SOURCE_SINK,
  "krx_bio",
  krx_ssl_bio_write,
  krx_ssl_bio_read,
  0,
  0,
  krx_ssl_bio_ctrl,
  krx_ssl_bio_create,
  krx_ssl_bio_destroy,
  0
};


/* Globals .. */
httpd_conn* hcon_ptr = NULL;
udp_conn* ucon_ptr = NULL;

int main() {

  /* dump previously recorded file */
#if 0
  printf("Opening recorded file.\n");
  krx_ivf_t ivf;
  krx_ivf_init(&ivf);
  krx_ivf_open(&ivf);
  krx_ivf_read_header(&ivf);
  krx_ivf_read_frame(&ivf);
  printf("----\n");
  return 0;
#endif  
  /* -------------------------------------------------- */

  udp_conn ucon;
  ucon.dtls.user = &ucon;
  ucon.dtls.type = KRX_DTLS_TYPE_SERVER;
  ucon.dtls.send = krx_send_to_browser;

  if(krx_dtls_init() < 0) {
    exit(EXIT_FAILURE);
  }

  if(krx_dtls_create(&ucon.dtls) < 0) {
    exit(EXIT_FAILURE);
  }

  if(krx_rtp_init(&ucon.rtp) < 0) {
    exit(EXIT_FAILURE);
  }

  /* WebRTC */
  ucon.port = 2233;
  ucon.ssl.user = &ucon;
  ucon_ptr = &ucon;
  
  /* SSL */
  if(krx_ssl_init(&ucon.ssl) < 0) {
    exit(EXIT_FAILURE);
  }

  /* SRTP */
  if(krx_init_srtp(&ucon.srtp) < 0) {
    exit(EXIT_FAILURE);
  }

  /* HTTP for signaling */
  httpd_conn hcon;
  hcon_ptr = &hcon;
  hcon.port = 3333;
  if(krx_httpd_init(&hcon) < 0) {
    exit(EXIT_FAILURE);
  }

  if(krx_udp_init(&ucon) < 0) {
    exit(EXIT_FAILURE);
  }

  if(krx_udp_bind(&ucon) < 0) {
    exit(EXIT_FAILURE);
  }

  signal(SIGINT, krx_udp_sighandler);

  while(must_run) {
    //printf("..\n");
    krx_udp_receive(&ucon);
    //sleep(1);
  }

  krx_dtls_shutdown();
}

void krx_udp_sighandler(int signum) {
  printf("Verbose: handled sig.\n");
  must_run = false;
  exit(EXIT_FAILURE);
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

  c->state = KRX_STATE_NONE;

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

void print_buffer(uint8_t *buf, size_t len) {
  int i;
  for(i = 0; i < len; ++i) {
    printf("%02X ", (unsigned char)buf[i]);
    if(i > 0 && i % 40 == 0) {
      printf("\n");
    }
  }
  printf("\n-\n");
}

int handle_stun(udp_conn* c, uint8_t *packet, size_t len) {

  StunAgent agent;
  StunValidationStatus status;
  StunAgentUsageFlags flags;
  StunMessage request;
  StunMessage response;
  int ret;
  size_t output_size;
  uint8_t output[1024];

  flags = STUN_AGENT_USAGE_IGNORE_CREDENTIALS; //  | STUN_AGENT_USAGE_USE_FINGERPRINT;  

  static const uint16_t attr[] = { 
    STUN_ATTRIBUTE_MAPPED_ADDRESS,
    STUN_ATTRIBUTE_RESPONSE_ADDRESS,
    STUN_ATTRIBUTE_CHANGE_REQUEST,
    STUN_ATTRIBUTE_SOURCE_ADDRESS,
    STUN_ATTRIBUTE_CHANGED_ADDRESS,
    STUN_ATTRIBUTE_USERNAME,
    STUN_ATTRIBUTE_PASSWORD,
    STUN_ATTRIBUTE_MESSAGE_INTEGRITY,
    STUN_ATTRIBUTE_ERROR_CODE,
    STUN_ATTRIBUTE_UNKNOWN_ATTRIBUTES,
    STUN_ATTRIBUTE_REFLECTED_FROM,
    STUN_ATTRIBUTE_CHANNEL_NUMBER,
    STUN_ATTRIBUTE_LIFETIME,
    STUN_ATTRIBUTE_MS_ALTERNATE_SERVER,
    STUN_ATTRIBUTE_MAGIC_COOKIE,
    STUN_ATTRIBUTE_BANDWIDTH,
    STUN_ATTRIBUTE_DESTINATION_ADDRESS,
    STUN_ATTRIBUTE_REMOTE_ADDRESS,
    STUN_ATTRIBUTE_PEER_ADDRESS,
    STUN_ATTRIBUTE_XOR_PEER_ADDRESS,
    STUN_ATTRIBUTE_DATA,
    STUN_ATTRIBUTE_REALM,
    STUN_ATTRIBUTE_NONCE,
    STUN_ATTRIBUTE_RELAY_ADDRESS,
    STUN_ATTRIBUTE_RELAYED_ADDRESS,
    STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS,
    STUN_ATTRIBUTE_REQUESTED_ADDRESS_TYPE,
    STUN_ATTRIBUTE_REQUESTED_PORT_PROPS,
    STUN_ATTRIBUTE_REQUESTED_PROPS,
    STUN_ATTRIBUTE_EVEN_PORT,
    STUN_ATTRIBUTE_REQUESTED_TRANSPORT,
    STUN_ATTRIBUTE_DONT_FRAGMENT,
    STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,
    STUN_ATTRIBUTE_TIMER_VAL,
    STUN_ATTRIBUTE_REQUESTED_IP,
    STUN_ATTRIBUTE_RESERVATION_TOKEN,
    STUN_ATTRIBUTE_CONNECT_STAT,
    STUN_ATTRIBUTE_PRIORITY,
    STUN_ATTRIBUTE_USE_CANDIDATE,
    STUN_ATTRIBUTE_OPTIONS,
    STUN_ATTRIBUTE_MS_VERSION,
    STUN_ATTRIBUTE_SOFTWARE,
    STUN_ATTRIBUTE_ALTERNATE_SERVER,
    STUN_ATTRIBUTE_FINGERPRINT,
    STUN_ATTRIBUTE_ICE_CONTROLLED,
    STUN_ATTRIBUTE_ICE_CONTROLLING,
    STUN_ATTRIBUTE_MS_SEQUENCE_NUMBER,
    STUN_ATTRIBUTE_CANDIDATE_IDENTIFIER
  };

  /* initialize our agent to be compatible with RFC5389 (= with TLS support) */
  output_size = 0;
  memset(output, 0, sizeof(output));
  stun_agent_init(&agent, attr, STUN_COMPATIBILITY_RFC5389, flags);

  /* validate the request */
  status = stun_agent_validate(&agent, &request, packet, len, NULL, NULL);
  print_stun_validation_status(status);

  /* check the class */
  StunClass request_class = stun_message_get_class(&request);
  print_stun_class(request_class);
  if(request_class == STUN_ERROR) {
    printf("Error: request stun class failed.\n");
    exit(0);
  }

  /* what stun method? */
  StunMethod request_method = stun_message_get_method(&request);
  print_stun_method(request_method);

  /* initialize the response */
  ret = stun_agent_init_response(&agent, &response, output, 1024, &request);
  printf("Stun agent_init_response ret: %d\n", ret);

  /* add xor-mapped-address */
  uint32_t magic_cookie = 0;
  uint8_t* cookie_ptr = NULL;
  StunTransactionId transid;
  socklen_t sock_len = 0;
  char client_ip[16] = { 0 } ;
  StunMessageReturn stun_ret = STUN_MESSAGE_RETURN_INVALID;

  stun_message_id(&response, transid);
  magic_cookie = *((uint32_t*)transid);
  sock_len = sizeof(c->client);
  cookie_ptr = (uint8_t*) &magic_cookie;
  inet_ntop(AF_INET, &c->client.sin_addr.s_addr, client_ip, sizeof(client_ip));

  stun_ret = stun_message_append_xor_addr(&response, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, (const struct sockaddr*)&c->client, sock_len);
  print_stun_message_return(stun_ret);

  printf("Received data from: %s\n", client_ip);
  printf("Magic cookie: %02X %02X %02X %02X\n", cookie_ptr[0], cookie_ptr[1], cookie_ptr[2], cookie_ptr[3]);
  
  // username
  // --------
  const char* username = NULL;
  uint16_t username_len = 0;
  username = (const char*)stun_message_find(&request, STUN_ATTRIBUTE_USERNAME, &username_len);
  printf("Username: %s, len: %d\n", username, (int)username_len);

#if 0
  if(username) {
    StunMessageReturn username_res = stun_message_append_bytes(&response, STUN_ATTRIBUTE_USERNAME, username, username_len);
    print_stun_message_return(username_res);

  }
  uint32_t fingerprint = 0;
  if(stun_message_find32(&request, STUN_ATTRIBUTE_FINGERPRINT, &fingerprint) == STUN_MESSAGE_RETURN_SUCCESS) {
    printf("Got fingerprint: %d\n", fingerprint);
    if(stun_message_append32(&response, STUN_ATTRIBUTE_FINGERPRINT, fingerprint) != STUN_MESSAGE_RETURN_SUCCESS) {
      printf("Error while adding the fingerprint.\n");
    }
  }
#endif

  // password
  const char* password = ucon_ptr->stun_pw; // "94ccca06d14fb48c135bdaff30560c4d";
  uint16_t password_len = strlen(password) + 1;
  output_size = stun_agent_finish_message(&agent, &response, (const uint8_t*) password, password_len);

  // answer to the connection
  krx_udp_send(c, output, output_size);

  print_buffer(output, output_size);
  return 0;
}

int krx_udp_receive(udp_conn* c) {

  socklen_t len = sizeof(c->client);
  int r = recvfrom(c->sock, c->buf, KRX_UDP_BUF_LEN, 0, (struct sockaddr*)&c->client, &len);

  if(r < 0) {
    printf("Error: cannot receive.\n");
    return -1;
  }
  if(r < 2) { 
    printf("Only received 2 bytes?\n");
    return 0;
  }

  if((c->buf[0] == 0x00 || c->buf[0] == 0x01) && (c->buf[1] == 0x00 || c->buf[1] == 0x01) ) {
    handle_stun(c, c->buf, r);
  }
  else {
    if(krx_dtls_is_handshake_done(&c->dtls) > 0) {
      if(c->state == KRX_STATE_NONE) {
        // when done, we pass on the data libsrtp

        c->state = KRX_STATE_SSL_INIT_READY;
        printf("---------------------- finished --------------------------\n");
        uint8_t material[KRX_SRTP_MASTER_LEN * 2];
        int r = SSL_export_keying_material(c->dtls.ssl, material, KRX_SRTP_MASTER_LEN * 2, 
                                           "EXTRACTOR-dtls_srtp", 19, NULL, 0, 0);

        if(r == 0) {
          printf("Error: cannot export the SSL keying material.\n");
          exit(EXIT_FAILURE);
        }
        
        // extracking keying example https://github.com/traviscross/baresip/blob/8974d662c942b10a9bb05223ddc7881896dd4c2f/modules/dtls_srtp/tls_udp.c
        /* Keys:: http://tools.ietf.org/html/rfc5764#section-4.2, note: client <> server use different keying, we handle server for now. */
        uint8_t* remote_key = material;
        uint8_t* local_key = remote_key + KRX_SRTP_MASTER_KEY_LEN;
        uint8_t* remote_salt = local_key + KRX_SRTP_MASTER_KEY_LEN;
        uint8_t* local_salt = remote_salt + KRX_SRTP_MASTER_SALT_LEN;;

        memcpy(c->srtp.policy.key, remote_key, KRX_SRTP_MASTER_KEY_LEN);
        memcpy(c->srtp.policy.key + KRX_SRTP_MASTER_KEY_LEN, remote_salt, KRX_SRTP_MASTER_SALT_LEN);

        SRTP_PROTECTION_PROFILE *p = SSL_get_selected_srtp_profile(c->dtls.ssl);
        if(!p) {
          printf("Error: cannot extract the srtp_profile.\n");
          exit(EXIT_FAILURE);
        }
        printf(">>>>>>> %s <<<<<\n", p->name);

        // TLS_RSA_WITH_AES_128_CBC_SHA 
        printf("---> cipher: %s\n", SSL_CIPHER_get_name(SSL_get_current_cipher(c->dtls.ssl)));

        printf("one\n");
        /* create SRTP session */
        err_status_t sr = srtp_create(&c->srtp.session, &c->srtp.policy);
        if(sr != err_status_ok) {
          printf("Error: cannot create srtp session: %d.\n", sr);
          exit(EXIT_FAILURE);
        }
        printf("two\n"); 

      }
      else if(c->state == KRX_STATE_SSL_INIT_READY) {
        int buflen = r;
        err_status_t sr = srtp_unprotect(c->srtp.session, c->buf, &buflen);
        
        if(sr != err_status_ok) {
          printf("Error: cannot unprotect, err: %d. len: %d <> %d\n", sr, len, buflen);
        }
        else {
          krx_rtp_decode(&c->rtp, c->buf, buflen);

          /*
          int nread = 0;
          int to_read = buflen;
          uint8_t* parse_buffer = c->buf;
          int total_read = 0;
          printf("~~\n");

          do { 

            nread = krx_rtp_decode(&c->rtp, parse_buffer, to_read);

            if(nread < 0) {
              break;
            }
            total_read += nread;
            to_read -= nread;
            printf("/ %d\n", total_read);
          } while (to_read > 0);
          */
        }

      }
      
    }
    else {
      krx_dtls_handle_traffic(&c->dtls, c->buf, r);
    }
  }
  return 0;
}

int krx_udp_send(udp_conn* c, uint8_t* buf, size_t len) {

  int r = sendto(c->sock, buf, len, 0, (struct sockaddr*)&c->client, sizeof(c->client));
  printf("Sending data on connection: %d, sock: %d\n", r, c->sock);

  return r;
}

void print_stun_validation_status(StunValidationStatus s) {
  switch(s) {
    case STUN_VALIDATION_SUCCESS:                   printf("StunValidationStatus: STUN_VALIDATION_SUCCESS\n");                    break;
    case STUN_VALIDATION_NOT_STUN:                  printf("StunValidationStatus: STUN_VALIDATION_NOT_STUN\n");                   break;
    case STUN_VALIDATION_INCOMPLETE_STUN:           printf("StunValidationStatus: STUN_VALIDATION_INCOMPLETE_STUN\n");            break;
    case STUN_VALIDATION_BAD_REQUEST:               printf("StunValidationStatus: STUN_VALIDATION_BAD_REQUEST\n");                break;
    case STUN_VALIDATION_UNAUTHORIZED_BAD_REQUEST:  printf("StunValidationStatus: STUN_VALIDATION_UNAUTHORIZED_BAD_REQUEST\n");   break;
    case STUN_VALIDATION_UNAUTHORIZED:              printf("StunValidationStatus: STUN_VALIDATION_UNAUTHORIZED\n");               break;
    case STUN_VALIDATION_UNMATCHED_RESPONSE:        printf("StunValidationStatus: STUN_VALIDATION_UNMATCHED_RESPONSE\n");         break;
    case STUN_VALIDATION_UNKNOWN_REQUEST_ATTRIBUTE: printf("StunValidationStatus: STUN_VALIDATION_UNKNOWN_REQUEST_ATTRIBUTE\n");  break;
    case STUN_VALIDATION_UNKNOWN_ATTRIBUTE:         printf("StunValidationStatus: STUN_VALIDATION_UNKNOWN_ATTRIBUTE\n");          break;
    default:                                        printf("StunValidationStatus: unknown status.\n");                            break;
  }
}

void print_stun_class(StunClass c) {
  switch(c) { 
    case STUN_REQUEST:     printf("StunClass: STUN_REQUEST.\n");     break;
    case STUN_INDICATION:  printf("StunClass: STUN_INDICATION.\n");  break;
    case STUN_RESPONSE:    printf("StunClass: STUN_RESPONSE.\n");    break;
    case STUN_ERROR:       printf("StunClass: STUN_ERROR.\n");       break;
    default:               printf("StunClass: unknown.\n");          break;
  }
}

void print_stun_method(StunMethod m) {
  switch(m) {
    case STUN_BINDING:            printf("StunMethod: STUN_BINDING.\n");                                       break;
    case STUN_SHARED_SECRET:      printf("StunMethod: STUN_SHARED_SECRET.\n");                                 break;
    case STUN_ALLOCATE:           printf("StunMethod: STUN_ALLOCATE.\n");                                      break;
    case STUN_REFRESH:            printf("StunMethod: STUN_REFRESH or STUN_SET_ACTIVE_DST or STUN_SEND.\n");   break;
    case STUN_CONNECT:            printf("StunMethod: STUN_CONNECT.\n");                                       break;
    case STUN_IND_SEND:           printf("StunMethod: STUN_IND_SEND or STUN_OLD_SET_ACTIVE_DST.\n");           break;
    case STUN_IND_DATA:           printf("StunMethod: STUN_IND_DATA.\n");                                      break;
    case STUN_CREATEPERMISSION:   printf("StunMethod: STUN_CREATEPERMISSION or STUN_IND_CONNECT_STATUS.\n");   break;
    case STUN_CHANNELBIND:        printf("StunMethod: STUN_CHANNELBIND.\n");                                   break;
    default:                      printf("StunMethod: unkown.\n");                                             break;
  }
}

void print_stun_message_return(StunMessageReturn r) {
  switch(r) {
    case STUN_MESSAGE_RETURN_SUCCESS:             printf("StunMessageReturn: STUN_MESSAGE_RETURN_SUCCESS.\n");             break;
    case STUN_MESSAGE_RETURN_NOT_FOUND:           printf("StunMessageReturn: STUN_MESSAGE_RETURN_NOT_FOUND.\n");           break;
    case STUN_MESSAGE_RETURN_INVALID:             printf("StunMessageReturn: STUN_MESSAGE_RETURN_INVALID.\n");             break;
    case STUN_MESSAGE_RETURN_NOT_ENOUGH_SPACE:    printf("StunMessageReturn: STUN_MESSAGE_RETURN_NOT_ENOUGH_SPACE.\n");    break;
    case STUN_MESSAGE_RETURN_UNSUPPORTED_ADDRESS: printf("StunMessageReturn: STUN_MESSAGE_RETURN_UNSUPPORTED_ADDRESS.\n"); break;
    default: printf("StunMessageReturn: unknown.\n"); break;
  }
}

/* HTTP */
/* ----------------------------------------------------------------------------- */
int krx_httpd_init(httpd_conn* c) {

  c->fd = socket(AF_INET, SOCK_STREAM, 0);
  if(c->fd < 0) {
    printf("Error: cannot setup httpd listener.\n");
    return -1;
  }

  /* reuse */
  int val = 1;
  int r = 0;
  r = setsockopt(c->fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
  if(r < 0) {
    printf("Error: cannot set REUSEADDR.\n");
    return -2;
  }

  c->saddr.sin_family = AF_INET;
  c->saddr.sin_addr.s_addr = INADDR_ANY;
  c->saddr.sin_port = htons(c->port);

  r = bind(c->fd, (struct sockaddr*)&c->saddr, sizeof(c->saddr));
  if(r < 0) {
    printf("Error: cannot bind the httpd socket.\n");
    return -2;
  }

  printf("Initialize http listener.\n");

  r = listen(c->fd, 5);
  if(r < 0) {
    printf("Error: cannot listen on the httpd socket.\n");
    return -3;
  }

  krx_httpd_receive((void*)c);

  return 0;
}

/*
  Extracts the password get variable that it receives from the index.html (see projects).
  We receive the ice-pwd value that we use in our stun response. 
*/
void krx_httpd_receive(httpd_conn *c) {

  httpd_conn* con = c;
  printf("httpd, start listening on: %d.\n", con->port);

  bool run = true;

  while(run) {

    /* accept new connection */
    struct sockaddr_in raddr;
    socklen_t raddr_len = sizeof(raddr);
    int fd = accept(con->fd, (struct sockaddr*) &raddr, &raddr_len);
    if(fd < 0) {
      printf("Error: while accepting on httpd.\n");
      exit(EXIT_FAILURE);
    }
    
    int nread = read(fd, con->buf, HTTPD_BUF_LEN);
    unsigned char* b = con->buf;

    for(int i = 0; i < nread - 3; ++i) {

      /* extract the passwd variable: /?passwd=[THE PASSWORD] */
      if(b[i+0] == 'G' && b[i+1] == 'E' && b[i+2] == 'T' && nread > 100) {
        bool must_copy = false;
        int copy_pos = 0;

        for(int j = i; j < nread; ++j) {

          if(b[j] == '=') {
            must_copy = true;
            continue;
          }

          if(must_copy && b[j] == ' ') {
            printf("Got password: '%s'\n", ucon_ptr->stun_pw);
            run = false;
            must_copy = false;

            close(fd);
            fd = -1;
            break;
          }

          if(must_copy) {
            ucon_ptr->stun_pw[copy_pos++] = b[j];
          }
        }
      }
    }
  }

  close(con->fd);

  printf("Closed httpd socket.\n");
}

/* S S L // D T L S */
/* -------------------------------------------------------------------------------- */

int krx_ssl_init(krx_ssl* k) {

  int r = 0;

  SSL_library_init();
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();
  
  /* create a new context using DTLS */
  k->ctx = SSL_CTX_new(DTLSv1_method());
  if(!k->ctx) {
    printf("Error: cannot create SSL_CTX.\n");
    ERR_print_errors_fp(stderr);
    return -1;
  }

  /* set our supported ciphers */

  //r = SSL_CTX_set_cipher_list(k->ctx, "DHE-RSA-AES128-GCM-SHA:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256");
  //r = SSL_CTX_set_cipher_list(k->ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
  //r = SSL_CTX_set_cipher_list(k->ctx, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
  r = SSL_CTX_set_cipher_list(k->ctx, "RSA:kDHE");
  if(r <= 0) {
    printf("Error: cannot set the cipher list.\n");
    ERR_print_errors_fp(stderr);
    return -2;
  }

  /* the client doesn't have to send it's certificate */
  SSL_CTX_set_verify(k->ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, krx_ssl_verify);
  //SSL_CTX_set_session_cache_mode(k->ctx, SSL_SESS_CACHE_OFF);
  //SSL_CTX_set_verify_depth(k->ctx, 4);
  SSL_CTX_set_mode(k->ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_AUTO_RETRY);

  /* enable srtp */
  r = SSL_CTX_set_tlsext_use_srtp(k->ctx, "SRTP_AES128_CM_SHA1_80");
  if(r != 0) {
    printf("Error: cannot setup srtp.\n");
    ERR_print_errors_fp(stderr);
    return -3;
  }

  /* load certificate and key */
  r = SSL_CTX_use_certificate_file(k->ctx, "./server-cert.pem", SSL_FILETYPE_PEM);
  if(r <= 0) {
    printf("Error: cannot load certificate file.\n");
    ERR_print_errors_fp(stderr);
    return -4;
  }

  r = SSL_CTX_use_PrivateKey_file(k->ctx, "./server-key.pem", SSL_FILETYPE_PEM);
  if(r <= 0) {
    printf("Error: cannot load private key file.\n");
    ERR_print_errors_fp(stderr);
    return -5;
  }

  r = SSL_CTX_check_private_key(k->ctx);
  if(r == 0) {
    printf("Error: checking the private key failed.\n");
    return -6;
  }

  k->conn_initialized = false; 
  k->in_pos = 0;
  k->in_len = 0;
  k->in_buf = NULL;
  k->out_pos = 0;
  k->out_len = 0;
  k->out_buf = NULL;

  return 0;
}

int krx_ssl_bio_create(BIO* b) {
  b->init = 1;
  b->num = 0;
  b->ptr = NULL;
  b->flags = 0;
  return 1;
}

int krx_ssl_bio_destroy(BIO* b) {
  if(b == NULL) {
    return 0;
  }
  
  b->ptr = NULL;
  b->init = 0;
  b->flags = 0;
  
  return 1;
}

int krx_ssl_bio_read(BIO* b, char* buf, int len) {
  printf("----- krx_ssl_bio_read() called with %d bytes.\n", len);
  int r = 0;
  int avail = 0;
  krx_ssl* krx = (krx_ssl*)b->ptr;
  
  avail = (krx->in_len - krx->in_pos);
  if(avail == 0) {
    printf("----- Error: avail is 0.\n");
    errno = EAGAIN;
    return -1;
  }

  if(len > avail) {
    r = avail;
  }
  else {
    r = len;
  }

  memcpy(buf, krx->in_buf + krx->in_pos, r);
  krx->in_pos += r;
  printf("----- krx_ssl_bio_read(), avail: %d\n", avail);
  return r;
}

int krx_ssl_bio_write(BIO* b, const char* buf, int len) {
  printf("----- krx_ssl_bio_write() called with %d bytes.\n", len);
  
  int w = 0;
  int avail = 0;
  krx_ssl* krx = (krx_ssl*)b->ptr;

  printf("----- krx_ssl_bio_write() krx->out_len: %d, krx->out_pos: %d.\n", krx->out_len, krx->out_pos);
  
  avail = (krx->out_len - krx->out_pos);
  if(avail == 0) {
    errno = EAGAIN;
    printf("----- Error: avail is 0.\n");
    return -1;
  }

  if(len > avail) {
    w = avail;
  }
  else {
    w = len;
  }

  memcpy(krx->out_buf + krx->out_pos, buf, w);
  krx->out_pos += w;

  return w;
}

long krx_ssl_bio_ctrl(BIO* b, int cmd, long num, void* ptr) {

  krx_ssl* krx = (krx_ssl*)b->ptr;

  switch (cmd) {
    case BIO_CTRL_FLUSH: {
      printf("----- DTLS: BIO_CTRL_FLUSH.\n");
      //int krx_udp_send(udp_conn* c, uint8_t* buf, size_t len);
      //printf("out_pos: %d\n", krx->out_pos);
      //krx_udp_send((udp_conn*)krx->user, krx->out_buf, 1120); /* just a hardcoded test; sends back serverhello */
      return 1;
    } 
    case BIO_CTRL_WPENDING: {
      printf("----- DTLS: BIO_CTRL_WPENDING: %ld.\n", num);
      return 0;
    }
    case BIO_CTRL_DGRAM_QUERY_MTU: {
      return 1472;
    }
    case BIO_CTRL_GET: {
      return BIO_TYPE_SOURCE_SINK;
    }
    default: {
      printf("----- DTLS: unhandled bio_ctrl: %d num: %ld\n", cmd, num);
      break;
    }
  }

  return 0;
}

/* initialize a new connection; @todo cleanup + free on failure */
int krx_ssl_conn_init(krx_ssl* k) {

  printf("------------ start initialize ssl_con -----------\n");

  if(k->conn_initialized) {
    printf("Error: already initialize the ssl connection.\n");
    return -1;
  }

  k->ssl = SSL_new(k->ctx);
  if(k->ssl == NULL) {
    printf("Error: cannot create the SSL object.\n");
    ERR_print_errors_fp(stderr);
    return -2;
  }

  k->in = BIO_new(&krx_bio);
  if(k->in == NULL) {
    printf("Error: cannot create the in BIO.\n");
    SSL_free(k->ssl);
    return -3;
  }

  k->out = BIO_new(&krx_bio);
  if(k->out == NULL) {
    BIO_free(k->in);
    SSL_free(k->ssl);
    return -4;
  }

  k->in->ptr = k;
  k->out->ptr = k;

  SSL_set_bio(k->ssl, k->in, k->out);

  SSL_set_accept_state(k->ssl);  /* set to accept state so it we act like we're a server */

  SSL_CTX_set_info_callback(k->ctx, krx_ssl_info_callback);

  k->conn_initialized = true; 

  printf("------------ end initialize ssl_con -----------\n");
  return 0;
}


void krx_ssl_info_callback(const SSL* ssl, int where, int ret) {

  if(ret == 0) {
    printf("-- krx_ssl_info_callback: error occured.\n");
    return;
  }

  SSL_WHERE_INFO(ssl, where, SSL_CB_LOOP, "LOOP");
  SSL_WHERE_INFO(ssl, where, SSL_CB_EXIT, "EXIT");
  SSL_WHERE_INFO(ssl, where, SSL_CB_READ, "READ");
  SSL_WHERE_INFO(ssl, where, SSL_CB_WRITE, "WRITE");
  SSL_WHERE_INFO(ssl, where, SSL_CB_ALERT, "ALERT");
  SSL_WHERE_INFO(ssl, where, SSL_CB_READ_ALERT, "READ ALERT");
  SSL_WHERE_INFO(ssl, where, SSL_CB_WRITE_ALERT, "WRITE ALERT");
  SSL_WHERE_INFO(ssl, where, SSL_CB_ACCEPT_LOOP, "ACCEPT LOOP");
  SSL_WHERE_INFO(ssl, where, SSL_CB_ACCEPT_EXIT, "ACCEPT EXIT");
  SSL_WHERE_INFO(ssl, where, SSL_CB_CONNECT_LOOP, "CONNECT LOOP");
  SSL_WHERE_INFO(ssl, where, SSL_CB_CONNECT_EXIT, "CONNECT EXIT");
  SSL_WHERE_INFO(ssl, where, SSL_CB_HANDSHAKE_START, "HANDSHAKE START");
  SSL_WHERE_INFO(ssl, where, SSL_CB_HANDSHAKE_DONE, "HANDSHAKE DONE");
}

int krx_ssl_encrypt(krx_ssl* k, uint8_t* out, int max, uint8_t* in, int len) {
  
  if(k == NULL) {
    printf("Error: `krx_ssl` in krx_ssl_encrypt is NULL.\n");
    return -1;
  }
  if(out == NULL) {
    printf("Error: `out` in krx_ssl_encrypt is NULL.\n");
    return -2;
  }
  if(in == NULL) {
    printf("Error: `in` in krx_ssl_encrypt is NULL.\n");
    return -3;
  }
  if(max < 0) {
    printf("Error: `max` in krx_ssl_encrypt is < 0.\n");
    return -4;
  }
  if(len < 0) {
    printf("Error: `len` in krx_ssl_encrypt is < 0.\n");
    return -5;
  }
  
  k->out_buf = out;
  k->out_len = max; // not len? 
  k->out_pos = 0; 
  
  int r = SSL_write(k->ssl, in, len);
  if(r < 0) {
    printf("Error: cannot encrypt.\n");
    ERR_print_errors_fp(stderr);
    return -6;
  }

  return r;
}

int krx_ssl_decrypt(krx_ssl* k, uint8_t* out, int max, uint8_t* in, int len) {

  if(k == NULL) {
    printf("Error: krx_ssl in krx_ssl_decrypt is NULL.\n");
    return -1;
  }
  if(in == NULL) {
    printf("Error: `in` in krx_ssl_decrypt is NULL.\n");
    return -2;
  }
  if(out == NULL) {
    printf("Error: `out` in krx_ssl_decrypt is NULL.\n");
    return -3;
  }
  if(len < 1) {
    printf("Error: `len` in krx_ssl_decrypt < 0. \n");
    return -4;
  }
  if(max < 1) {
    printf("Error: `max` in krx_ssl_decrypt < 0. \n");
    return -5;
  }

  printf("krx_ssl_decrypt, max: %d, len: %d\n", max, len);

  k->in_buf = in;
  k->in_len = len;
  k->in_pos = 0;

  int r = SSL_read(k->ssl, out, max);
  if(r < 0) {
    printf("Error: cannot decrypt.\n");
    ERR_print_errors_fp(stderr);
    return -6;
  }

  return r;
}

int krx_ssl_verify(int ok, X509_STORE_CTX* ctx) {
  printf("krx_ssl_verify: ok: %d\n", ok);
  return 1;
}

// @todo(roxlu):  implement
int krx_ssl_print_fingerprint(krx_ssl* k) {

  uint8_t fp[4096] = { 0 } ;
  uint8_t fp_string[4096] = { 0 };
  uint32_t fp_len = 4096;
  int r = 0;

  /*
  ret = X509_digest(cert, EVP_sha256(), fingerprint, &fingerprint_len);
  if (ret != 1) {
    printke("X509_digest");
    exit(1);
  }
  for (i = 0; i < fingerprint_len; i++) {
    if (i > 0) {
      pos += snprintf(fingerprint_string + pos, TEST_SZ - pos, ":");
    }
    pos += snprintf(fingerprint_string + pos, TEST_SZ - pos, "%02X", fingerprint[i]);
  }
  printk("%s", str);
  printk("a=fingerprint:sha-256 %s", fingerprint_string);
   */
  
  

  return 0;
}

/* S R T P */
/* -------------------------------------------------------------------------------- */

int krx_init_srtp(krx_srtp* s) {
  printf("Setting up srtp.\n");
  
  /* initialize */
  err_status_t err = err_status_ok;
  err = srtp_init();
  if(err != err_status_ok) {
    printf("error, code: %d\n", err);
    return -1;
  }
  // see http://mxr.mozilla.org/mozilla-central/source/media/webrtc/signaling/src/mediapipeline/SrtpFlow.cpp
  //crypto_policy_set_rtp_default(&s->policy.rtp);
  //crypto_policy_set_rtcp_default(&s->policy.rtcp);
  crypto_policy_set_aes_cm_128_hmac_sha1_80(&s->policy.rtp); // see SSL_get_selected_srtp_profile() to extract the name
  crypto_policy_set_aes_cm_128_hmac_sha1_80(&s->policy.rtcp); 

  s->policy.ssrc.type = ssrc_any_inbound; 
  s->policy.key = calloc(1, KRX_SRTP_MASTER_LEN); // @todo(roxlu): make sure to free somewhere
  s->policy.window_size = 1024;  // see: http://mxr.mozilla.org/mozilla-central/source/media/webrtc/signaling/src/mediapipeline/SrtpFlow.cpp
  s->policy.allow_repeat_tx = 1; // see:  http://mxr.mozilla.org/mozilla-central/source/media/webrtc/signaling/src/mediapipeline/SrtpFlow.cpp
  s->policy.window_size = 128;  // see: http://mxr.mozilla.org/mozilla-central/source/media/webrtc/signaling/src/mediapipeline/SrtpFlow.cpp
  s->policy.allow_repeat_tx = 0; // see:  http://mxr.mozilla.org/mozilla-central/source/media/webrtc/signaling/src/mediapipeline/SrtpFlow.cpp

  s->policy.next = NULL;


  /*
policy.ssrc.type = inbound ? ssrc_any_inbound : ssrc_any_outbound;
77   policy.ssrc.value = 0;
78   policy.ekt = nullptr;
79   policy.window_size = 1024;   // Use the Chrome value.  Needs to be revisited.  Default is 128
80   policy.allow_repeat_tx = 1;  // Use Chrome value; needed for NACK mode to work
81   policy.next = nullptr;
   */
  
  if(s->policy.key == NULL) {
    printf("Error: cannot allocate the policy key.\n");
    return -1;
  }

  return 0;
}

/* K R X _ D T L S */
/* -------------------------------------------------------------------------------- */
int krx_send_to_browser(krx_dtls_t* k, uint8_t* data, int len) {
  printf("Must send something to browser: %d\n", len);
  udp_conn* c = (udp_conn*)k->user;
  return krx_udp_send(c, data, len);
}
