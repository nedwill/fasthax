#ifndef __HEAP_H
#define __HEAP_H

extern char *fake_heap_start;
extern char *fake_heap_end;

u32 __ctru_heap;
u32 __ctru_heap_size;
u32 __ctru_linear_heap;
u32 __ctru_linear_heap_size;

/* This is important. */
#define LINEAR_HEAP_SIZE 0x03000000

/* Overwrite allocateHeaps in ctrulib so we get enough linear heap. */
void __system_allocateHeaps(void);

#endif /* __HEAP_H */
