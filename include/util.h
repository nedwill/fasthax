#ifndef __UTIL_H
#define __UTIL_H

#define CONVERT_VA_L2_TO_PA(addr) ((addr) - 0xFFF00000 + 0x1FF80000)
#define CONVERT_PA_TO_VA_L1(addr) ((addr) - 0x1FF00000 + 0xDFF00000)
#define CONVERT_VA_L2_TO_L1(addr) ((addr) - 0xFFF00000 + 0xDFF80000)

void wait_for_user(void);

void *kernel_va_to_pa(const void *addr);
void flush_caches(void);

#endif /* __UTIL_H */
