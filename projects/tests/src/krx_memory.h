/*

  krx_mem
  --------
  
  Very simplistic memory management feature. This is my first attempt 
  to create some sort of memory management thing in C. Note that I'm 
  pretty sure there are better ways ... coming from a c++ world where 
  I'm used to std::vector doing everything for me. Goal of `krx_mem`
  is to have simply a couple of memory blocks which are preallocated and
  can be reused once made free again. 

 */
#ifndef KRX_MEMORY_H
#define KRX_MEMORY_H

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

typedef struct krx_mem krx_mem;
typedef struct krx_mem_block krx_mem_block;

struct krx_mem_block {
  uint8_t* buf;
  uint32_t size;
  uint8_t is_free;
  krx_mem_block* next;
};

struct krx_mem {
  krx_mem_block* block;
};

krx_mem* krx_mem_alloc(uint32_t size, int numblocks);          /* allocate `numblocks` memory blocks with a size of `size` */
void krx_mem_dealloc(krx_mem* m);                              /* deallocates all allocated memory */
krx_mem_block* krx_mem_get_free(krx_mem* m);                   /* returns a free memory block and makes sure the is_free flag is set to 0 (false). or returns NULL when no free block exists. use krx_mem_set_free() to make the block free again. */
int krx_mem_set_free(krx_mem* m, krx_mem_block* b);            /* frees the block for the given address */
krx_mem_block* krx_mem_find_block(krx_mem* m, uint8_t* ptr);   /* get the memory block for the given uint8_t* ptr. */

#endif
