#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sofia-sip/sdp.h>

void sighandler(int signum);

typedef struct krx_sdp krx_sdp;

struct krx_sdp {
  sdp_parser_t* parser;
  sdp_session_t* session;
  su_home_t* home;
};

int read_file(const char* path, char* buf, int len);

int krx_sdp_init(krx_sdp* k);
int krx_sdp_parse(krx_sdp* k, const char* buf, issize_t len);
int krx_sdp_shutdown(krx_sdp* k);

const char* krx_sdp_proto_to_string(sdp_proto_e e);
const char* krx_sdp_addrtype_to_string(sdp_addrtype_e e);
const char* krx_sdp_nettype_to_string(sdp_nettype_e e);

int main() {

  char buf[1024];
  int nbytes = read_file("sdp.txt", buf, sizeof(buf));
  if(nbytes < 0) {
    printf("Error: cannot read file.\n");
    exit(0);
  }

  printf("\n\nSDP Parser Test. Read: %d\n\n", nbytes);

  krx_sdp k;
  if(krx_sdp_init(&k) < 0) {
    exit(1);
  }

  krx_sdp_parse(&k, buf, nbytes);

  krx_sdp_shutdown(&k);

  printf("\n\n");
  return 0;
}

void sighandler(int signum) {
  printf("Received SIGINT.\n");
  exit(0);
}

int krx_sdp_init(krx_sdp* k) {

  if(!k) {
    printf("Error: krx_sdp_init(), invalid pointer.\n");
    return -1;
  }

  k->home = su_home_new(sizeof(su_home_t));
  if(!k->home) {
    printf("Error: krx_sdp_init(), cannot allocate a su_home_t.\n");
    return -2;
  }

  if(su_home_init(k->home) < 0) {
    printf("Error: krx_sdp_init(), cannot su_home_init().\n");
    return -3;
  }

  k->parser = NULL;
  k->session = NULL;

  return 0;
}

int krx_sdp_shutdown(krx_sdp* k) {

  if(!k) {
    printf("Error: krx_sdp_shutdown(), invalid pointer.\n");
    return -1;
  }

  if(k->parser) {
    sdp_parser_free(k->parser);
    k->parser = NULL;
  }

  if(k->home) {
    su_home_deinit(k->home);
    k->home = NULL;
  }

  return 0;
}

int krx_sdp_parse(krx_sdp* k, const char* buf, issize_t len) {
  
  if(!k) {
    printf("Error: krx_sdp_parse(), invalid pointer.\n");
    return -1;
  }

  if(!buf) {
    printf("Error: krx_sdp_parse(), invalid buffer.\n");
    return -2;
  }

  if(len <= 0) {
    printf("Error: krx_sdp_parse(), invalid len.\n");
    return -3;
  }

  k->parser = sdp_parse(k->home, buf, len, 0);
  k->session = sdp_session(k->parser);

  if(!k->session) {
    printf("Error: krx_sdp_parse() failed: %s\n", sdp_parsing_error(k->parser));
    printf("@todo(roxlu): should we cleanup here??\n");
    return -4;
  }

  /* print out the attributes */
  sdp_attribute_t* a = k->session->sdp_attributes;
  while(a) {
    if(a->a_name) {
      printf("Attribute: %s = %s\n", a->a_name, a->a_value);
    }
    a = a->a_next;
  }

  /* print the media */
  sdp_media_t* m = k->session->sdp_media;
  while(m) {
    if(m->m_type == sdp_media_audio) {
      printf("Audio media type. port: %lu\n", m->m_port);
    }
    else if(m->m_type == sdp_media_video) {

      /* media type */
      printf("Video media type. port: %lu, number of ports: %lu, proto: %s / %s\n", 
             m->m_port, 
             m->m_number_of_ports, 
             m->m_proto_name, 
             krx_sdp_proto_to_string(m->m_proto));

      sdp_list_t* f = m->m_format;
      while(f) {
        printf("\tFormat: %s\n", f->l_text);
        f = f->l_next;
      }

      /* connections (candidates) */
      sdp_connection_t* c = m->m_connections;
      while(c) {
        printf("\tConnection: %s (%s / %s)\n", 
               c->c_address, 
               krx_sdp_nettype_to_string(c->c_nettype), 
               krx_sdp_addrtype_to_string(c->c_addrtype));
        c = c->c_next;
      }

      /* rtpmap */
      sdp_rtpmap_t* map = m->m_rtpmaps;
      while(map) {
        printf("\tRTP map: %s\n", map->rm_encoding);
        map = map->rm_next;
      }

    }
    else {
      printf("Unhandled media type.\n");
    }

    sdp_attribute_t* a = m->m_attributes;
    while(a) {
      if(a->a_name) {
        printf("\t%s=%s\n", a->a_name, a->a_value);
      }
      a = a->a_next;
    }

    m = m->m_next;
  }

  return 0;
}

int read_file(const char* path, char* buf, int len) {

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

const char* krx_sdp_proto_to_string(sdp_proto_e e) { 
  switch(e) {
    case sdp_proto_x: return "Unknown transport";
    case sdp_proto_tcp: return "TCP";
    case sdp_proto_udp: return "UDP";
    case sdp_proto_rtp: return "RTP/AVP";
    case sdp_proto_srtp: return "RTP/SAVP";
    case sdp_proto_udptl: return "UDPTL";
    case sdp_proto_tls: return "TLS over TCP";
    case sdp_proto_any: return "wildcard";
    default: return "Unknown."; 
  }
}

const char* krx_sdp_addrtype_to_string(sdp_addrtype_e e) {
  switch(e) {
    case sdp_addr_x: return "Unknown address type";
    case sdp_addr_ip4: return "IPv4 address";
    case sdp_addr_ip6: return "IPv6 address";
    default: return "Unknown.";
  }
}

const char* krx_sdp_nettype_to_string(sdp_nettype_e e) {
  switch(e) {
    case sdp_net_x: return "Unknown network type.";
    case sdp_net_in: return "Internet";
    default: return "Unknown.";
  }
}
