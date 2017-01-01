/* Backdoor helper functions. Ned Williamson 2016 */

#include <3ds.h>
#include <stdio.h>
#include <string.h>

#include "backdoor.h"
#include "util.h"

/* */
/* https://www.3dbrew.org/wiki/Virtual_address_mapping_New3DS_v9.2 */
/* [L2L] VA fff00000..fff20000 -> PA 1ff80000..1ffa0000 [  X ] [ Priv: R-, User: -- ] */
/* [L1 ] VA dff00000..e0000000 -> PA 1ff00000..20000000 [ XN ] [ Priv: RW, User: -- ] */
//
#define SVC_HANDLER_TABLE 0xFFF0230C
#define SVC_HANDLER_TABLE_PA (SVC_HANDLER_TABLE - 0xfff00000 + 0x1ff80000)
#define SVC_HANDLER_TABLE_WRITABLE (SVC_HANDLER_TABLE_PA - 0x1ff00000 + 0xdff00000)
/* overwrite SendSyncRequest3 since it's stubbed but we always have permission */
#define SEND_SYNC_REQUEST3 0x30
#define CURRENT_PROCESS 0xFFFF9004
#define HANDLE_TABLE_OFFSET 0xDC

static u32 *writeint_arg_addr;
static u32 writeint_arg_value;
static u32 *readint_arg;
static u32 readint_res;
static void *memcpy_src;
static void *memcpy_dst;
static u64 memcpy_len;
static Handle get_object_handle = 0;
static void *get_object_ret = NULL;
void *(*handle_lookup_kern)(void *, u32);

static void writeint() { *writeint_arg_addr = writeint_arg_value; }

static void memcpy_int() {
  memcpy(memcpy_dst, memcpy_src, memcpy_len);
}

void kmemcpy(void *dst, void *src, u32 len) {
  memcpy_dst = dst;
  memcpy_src = src;
  memcpy_len = len;
  svcMyBackdoor((s32(*)(void)) & memcpy_int);
}

void kwriteint(u32 *addr, u32 value) {
  writeint_arg_addr = addr;
  writeint_arg_value = value;
  svcMyBackdoor((s32(*)(void)) & writeint);
}

static void readint() { readint_res = *readint_arg; }

u32 kreadint(u32 *addr) {
  if (addr == 0) {
    printf("kreadint(NULL) -> 0\n");
    return 0;
  }
  readint_arg = addr;
  svcMyBackdoor((s32(*)(void)) & readint);
  return readint_res;
}

bool mybackdoor_installed() {
  /* kwriteint won't have a side effect if it's not installed.
   * that svc is normally callable by userspace but returns
   * an error.
   */
  static u32 installed = 0;
  kwriteint(&installed, 1);
  return installed;
}

void kwriteint_real(u32 *addr, u32 value) {
  writeint_arg_addr = addr;
  writeint_arg_value = value;
  svcMyBackdoor2((s32(*)(void)) & writeint);
}

bool realbackdoor_installed() {
  /* kwriteint won't have a side effect if it's not installed.
   * that svc is normally callable by userspace but returns
   * an error.
   */
  static u32 installed = 0;
  kwriteint_real(&installed, 1);
  return installed;
}

void print_array_wait(char *name, u32 *addr, u32 size) {
  if (!mybackdoor_installed()) {
    printf("can't print array, no backdoor\n");
    return;
  }
  if (!name || !addr || !size) {
    printf("print_array_wait: invalid arg provided.\n");
    return;
  }
  for (u32 i = 0; i < size / 4; i++) {
    printf("%s[%ld]: 0x%lx\n", name, i, kreadint(&addr[i]));
    if (i && (i % 16 == 0)) {
      printf("still going: waiting for <start>\n");
      wait_for_user();
    }
  }
  printf("finished: waiting for <start>\n");
  wait_for_user();
  svcSleepThread(100000000);
}

static void kdisable_interrupts() {
  asm volatile ("\tcpsid aif\n");
}

static void kernel_get_object_addr() {
  kdisable_interrupts();
  Handle handle = get_object_handle;
  u32 current_process = *(u32 *)CURRENT_PROCESS;
  u32 process_handle_table = current_process + HANDLE_TABLE_OFFSET;
  get_object_ret = handle_lookup_kern((void *)process_handle_table, handle);
}

void *get_object_addr(Handle handle) {
  if (!mybackdoor_installed()) {
    printf("get_object_addr: mybackdoor not installed.\n");
    return NULL;
  }
  get_object_handle = handle;
  svcMyBackdoor((s32(*)(void)) & kernel_get_object_addr);
  if (get_object_ret) {
    u32 *obj = get_object_ret;
    u32 *refcount_addr = &obj[1];
    u32 refcount = kreadint(refcount_addr);
    if (refcount > 0) {
      kwriteint(refcount_addr, refcount - 1);
    } else {
      printf("wtf? object is in table with 0 refcount?");
    }
  }
  return get_object_ret;
}

unsigned int (*RandomStub)(u32 *, u32 *);
static void *randomstub_arg = NULL;

static void randomstub_wrapper() {
  if (!randomstub_arg) {
    return;
  }
  RandomStub(randomstub_arg, (void*)RandomStub);
}

void kernel_randomstub(u32 *arg) {
  if (!arg) {
    printf("kernel_randomstub: invalid arg\n");
    return;
  }
  randomstub_arg = arg;
  svcMyBackdoor((s32(*)(void)) & randomstub_wrapper);
}

static Result kernel_backdoor(s32 (*callback)(void)) { return callback(); }

bool backdoor_installed = false;

void install_kernel_backdoor() {
  backdoor_installed = true;
  u32 *svc_table = (u32 *)SVC_HANDLER_TABLE_WRITABLE;
  svc_table[SEND_SYNC_REQUEST3] = (u32)&kernel_backdoor;
}

bool get_timer_value(Handle timer, u64 *initial, u64 *interval) {
  u64 *timer_addr = (u64 *)get_object_addr(timer);
  if (!timer_addr) {
    printf("get_timer_value: get_object_addr failed\n");
    return false;
  }

  if (initial) {
    kmemcpy(initial, &timer_addr[6], sizeof(u64));
  }

  if (interval) {
    kmemcpy(interval, &timer_addr[5], sizeof(u64));
  }

  return true;
}
