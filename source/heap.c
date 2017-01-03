/* Adapted from ctrulib. Thanks smea. */

#include <3ds.h>
#include "heap.h"

void __system_allocateHeaps(void) {
  u32 tmp = 0;

  u32 size = osGetMemRegionFree(MEMREGION_APPLICATION);
  /* TODO: record a smaller size so ctrulib doesn't alloc over the exploited
   * object.
   */
  __ctru_linear_heap_size = LINEAR_HEAP_SIZE;
  __ctru_heap_size = size - __ctru_linear_heap_size;

  __ctru_heap = 0x08000000;
  svcControlMemory(&tmp, __ctru_heap, 0x0, __ctru_heap_size, MEMOP_ALLOC,
                   MEMPERM_READ | MEMPERM_WRITE);

  svcControlMemory(&__ctru_linear_heap, 0x0, 0x0, __ctru_linear_heap_size,
                   MEMOP_ALLOC_LINEAR, MEMPERM_READ | MEMPERM_WRITE);

  fake_heap_start = (char *)__ctru_heap;
  fake_heap_end = fake_heap_start + __ctru_heap_size;
}
