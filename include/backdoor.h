#ifndef __BACKDOOR_H
#define __BACKDOOR_H

#include <3ds.h>

bool backdoor_installed;

/* ASM SVC stubs */
Result svcMyBackdoor(s32 (*callback)(void));
Result svcGlobalBackdoor(s32 (*callback)(void));

/* Luma backdoor */
void kmemcpy(void *dst, void *src, u32 len);
void kwriteint(u32 *addr, u32 value);
u32 kreadint(u32 *addr);
bool mybackdoor_installed();
void print_array_wait(char *name, u32 *addr, u32 size);
void *get_object_addr(Handle handle);
/* Used in testing exploit */
void kernel_randomstub(u32 *arg);
bool get_timer_value(Handle timer, u64 *initial, u64 *interval);

/* Real backdoor */
u32 kreadint_real(u32 *addr);
void kwriteint_real(u32 *addr, u32 value);
bool global_backdoor_installed(void);
/* Used in real exploit, must be called from kernel mode. */
void install_global_backdoor(void);
bool finalize_global_backdoor(void);
void uninstall_global_backdoor(void);

#endif /* __BACKDOOR_H */
