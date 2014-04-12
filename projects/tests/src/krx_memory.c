#include "krx_memory.h"

static krx_mem_block* krx_mem_block_alloc(uint32_t size);
static void krx_mem_block_dealloc(krx_mem_block* b);

/* -------------------------------------------------- */

krx_mem* krx_mem_alloc(uint32_t size, int num_blocks) {

  krx_mem* m = (krx_mem*)malloc(sizeof(krx_mem));
  if(!m) {
    return NULL;
  }
  m->block = NULL;

  for(int i = 0; i < num_blocks; ++i) {
    krx_mem_block* block = krx_mem_block_alloc(size);
    if(!block) {
      printf("Error cannot allocate memory block.\n");
      exit(1);
    }
    block->next = m->block;
    m->block = block;
  }  

  return m;
}

krx_mem_block* krx_mem_get_free(krx_mem* m) {
  if(!m) { return NULL; } 
  krx_mem_block* block = m->block;
  while(block) {
    if(block->is_free) {
      block->is_free = 0;
      return block;
    }
    block = block->next;
  }
  return NULL;
}

int krx_mem_set_free(krx_mem* m, krx_mem_block* b) { 
  if(!m) { return -1; } 
  if(!b) { return -2; } 

  krx_mem_block* block = m->block;

  while(block) {
    if(block == b) {
      block->is_free = 1;
      return 0;
    }
  }

  return -3;
}

krx_mem_block* krx_mem_find_block(krx_mem* m, uint8_t* ptr) {
  if(!m) { return NULL; } 
  if(!ptr) { return NULL; } 

  krx_mem_block* block = m->block;

  while(block) {
    if(block->buf == ptr) {
      return block;
    }
  }

  return NULL;
}

void krx_mem_dealloc(krx_mem* m) {
  if(!m) { return ; } 

  krx_mem_block* block = m->block;
  while(block) {
    krx_mem_block* next = block->next;
    krx_mem_block_dealloc(block);
    block = next;
    free(next);
  }
}

/* -------------------------------------------------- */

/* allocate a new krx_mem_block with a certain size */
static krx_mem_block* krx_mem_block_alloc(uint32_t size) {

  krx_mem_block* mem = (krx_mem_block*)malloc(sizeof(krx_mem_block));
  if(!mem) {
    return NULL;
  }

  mem->buf = (uint8_t*)malloc(size);
  if(!mem->buf) {
    free(mem);
    return NULL;
  }

  mem->size = size;
  mem->next = NULL;
  mem->is_free = 1;

  return mem;
}

/* cleans up a krx_mem_block */
static void krx_mem_block_dealloc(krx_mem_block* b) {
  if(!b) { return ; } 
  
  free(b->buf);
  b->buf = NULL;
  b->size = 0;
  b->is_free = 0;
  b->next = NULL;
}
