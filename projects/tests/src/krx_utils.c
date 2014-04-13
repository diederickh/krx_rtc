#include "krx_utils.h"

int krx_stricmp(char const* s1, char const* s2) {
  if(s1 == s2) {
    return 0;
  }

  if(s1 == NULL || s2 == NULL) {
    return -1;
  }

  for(;;) {
    unsigned char a = *s1++, b = *s2++;

    if(b == 0) {
      return (a == b) ? 0 : -1;
    }

    if(a == b) {
      continue;
    }

    if('A' <= a && a <= 'Z') {
      if(a + 'a' - 'A' != b) {
        return -1;
      }
    }
    else if('A' <= b && b <= 'Z') {
      if(a != b + 'a' - 'A') {
        return -1;
      }
    }
    else {
      return -1;
    }
  }
}

int krx_strnicmp(const char* s1, const char* s2, size_t n) {

  if(n == 0) {
    return -1;
  }

  if(s1 == s2) {
    return -1;
  }

  if(s1 == NULL || s2 == NULL) {
    return -1;
  }

  if(strncmp(s1, s2, n) == 0) {
    return 0;
  }

  while(n-- > 0) {
    unsigned char a = *s1++, b = *s2++;

    if(a == 0 || b == 0) {
      return (a == b) ? 0 : -1;
    }

    if(a == b) {
      continue;
    }

    if('A' <= a && a <= 'Z') {
      if (a + 'a' - 'A' != b) {
        return -1;
      }
    }
    else if('A' <= b && b <= 'Z') {
      if(a != b + 'a' - 'A') {
        return -1;
      }
    }
    else {
      return -1;
    }
  }
}

int krx_read_file(const char* path, char* buf, int len) {
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

void krx_write_u8(uint8_t** buf, uint8_t value) {
  uint8_t* p = *buf;
  *p = value;
  *buf = p + 1;
}

void krx_write_be_u16(uint8_t** buf, uint16_t value) {
  uint8_t* b = (uint8_t*)&value;
  krx_write_u8(buf, b[1]);
  krx_write_u8(buf, b[0]);
}

void krx_write_be_u32(uint8_t** buf, uint32_t value) {
  uint8_t* b = (uint8_t*)&value;
  krx_write_u8(buf, b[3]);
  krx_write_u8(buf, b[2]);
  krx_write_u8(buf, b[1]);
  krx_write_u8(buf, b[0]);
}

uint8_t krx_read_u8(uint8_t** buf) {
  uint8_t* ptr = *buf;
  uint8_t result = *ptr;
  *buf = ptr + 1;
  return result;
}

uint16_t krx_read_be_u16(uint8_t** buf) {
  uint8_t* ptr = *buf;
  uint16_t result = 0;
  uint8_t* v = (uint8_t*)&result;
  v[0] = ptr[1];
  v[1] = ptr[0];
  *buf = ptr + 2;
  return result;
}

uint32_t krx_read_be_u32(uint8_t** buf) {
  uint8_t* ptr = *buf;
  uint32_t result = 0;
  uint8_t* v = (uint8_t*)&result;
  v[0] = ptr[3];
  v[1] = ptr[2];
  v[2] = ptr[1];
  v[3] = ptr[0];
  *buf = ptr + 4;
  return result;
}


int krx_hexdump(uint8_t* buf, int nbytes) {
  if(!buf) { return -1; } 
  if(!nbytes) { return -2; }

  /* we limit this a bit... */
  if(nbytes > 100) {
    nbytes = 100;
  }

  int c = 0;
  for(int i = 0; i < nbytes; ++i) {
    printf("%02X ", buf[i]);

    c++;
    if(c >= 80) {
      printf("\n");
    }
  }
  printf("\n");
  return 0;
}
