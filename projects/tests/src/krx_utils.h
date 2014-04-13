#ifndef KRX_UTILS_H
#define KRX_UTILS_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* string manipulation, file utils */
int krx_hexdump(uint8_t* buf, int nbytes);
int krx_stricmp(const char* s1, const char* s2);             /* case insensitive string compare. accepts NULL, will return -1 when they don't match or if strings are NULL else 0 */
int krx_strnicmp(const char* s1, const char* s2, size_t n);  /* case insensitive string compare up to N-chars. accepts NULL, will return -1 when they don't match or if string are NULL, else 0 */
int krx_read_file(const char* path, char* buf, int len);     /* read a file into the buffer */

/* reading from a buffer while moving the pointer */
void krx_write_u8(uint8_t** buf, uint8_t value);
void krx_write_be_u16(uint8_t** buf, uint16_t value);
void krx_write_be_u32(uint8_t** buf, uint32_t value);

/* writing to a buffer while moving the pointer */
uint8_t krx_read_u8(uint8_t** buf);
uint16_t krx_read_be_u16(uint8_t** buf);
uint32_t krx_read_be_u32(uint8_t** buf);

#endif
