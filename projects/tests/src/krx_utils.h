#ifndef KRX_UTILS_H
#define KRX_UTILS_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>

int krx_hexdump(uint8_t* buf, int nbytes);
int krx_stricmp(const char* a, const char* b);  /* case insensitive string compare. accepts NULL, will return -1 when they don't match or if strings are NULL else 0 */
void krx_write_u8(uint8_t** buf, uint8_t value);
void krx_write_be_u16(uint8_t** buf, uint16_t value);
void krx_write_be_u32(uint8_t** buf, uint32_t value);
uint8_t krx_read_u8(uint8_t** buf);
uint16_t krx_read_be_u16(uint8_t** buf);
uint32_t krx_read_be_u32(uint8_t** buf);

#endif
