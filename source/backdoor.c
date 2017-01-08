/* Backdoor helper functions. Ned Williamson 2016 */

#include <3ds.h>
#include <stdio.h>
#include <string.h>

#include "backdoor.h"
#include "util.h"

/* overwrite SendSyncRequest3 since it's stubbed but we always have permission */
#define SEND_SYNC_REQUEST3 0x30
#define SVC_BACKDOOR_NUM 0x7B
#define CURRENT_PROCESS 0xFFFF9004
#define HANDLE_TABLE_OFFSET ((is_n3ds) ? 0xDC : 0xD4)

#define EXC_VA_START  ((u32*)0xFFFF0000)
#define AXIWRAMDSP_RW_MAPPING_OFFSET (0xDFF00000 - 0x1FF00000)

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
void **svc_handler_table_writable;
u32 *svc_acl_check_writable;

extern bool is_n3ds;

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

u32 kreadint_real(u32 *addr) {
  if (addr == 0) {
    printf("kreadint(NULL) -> 0\n");
    return 0;
  }
  readint_arg = addr;
  svcGlobalBackdoor((s32(*)(void)) & readint);
  return readint_res;
}

void kwriteint_real(u32 *addr, u32 value) {
  writeint_arg_addr = addr;
  writeint_arg_value = value;
  svcGlobalBackdoor((s32(*)(void)) & writeint);
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

void kwriteint_global_backdoor(u32 *addr, u32 value) {
  writeint_arg_addr = addr;
  writeint_arg_value = value;
  svcGlobalBackdoor((s32(*)(void)) & writeint);
}

bool global_backdoor_installed() {
  /* kwriteint won't have a side effect if it's not installed.
   * that svc is normally callable by userspace but returns
   * an error.
   */
  static u32 installed = 0;
  kwriteint_global_backdoor(&installed, 1);
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

/* currently unused. if people don't like the unprivileged backdoor
 * we can use this to restore send_synd_request3 and give kernel
 * access by some other means.
 */
void *send_sync_request3_orig = NULL;
void *svc_backdoor_orig = NULL;

/* must be called in kernel mode */
void install_global_backdoor() {
  if (send_sync_request3_orig == NULL) {
    send_sync_request3_orig = svc_handler_table_writable[SEND_SYNC_REQUEST3];
    svc_backdoor_orig = svc_handler_table_writable[SVC_BACKDOOR_NUM];
  }
  svc_handler_table_writable[SEND_SYNC_REQUEST3] = &kernel_backdoor;
}

/* must be called in kernel mode */
void uninstall_global_backdoor() {
  svc_handler_table_writable[SEND_SYNC_REQUEST3] = send_sync_request3_orig;
  svc_handler_table_writable[SVC_BACKDOOR_NUM] = svc_backdoor_orig;
}

/* adapted from Luma, thanks, just rushing to finish this! */
static u8 backdoor_code[40] =
  { 0xFF, 0x10, 0xCD, 0xE3, 0x0F, 0x1C, 0x81, 0xE3, 0x28, 0x10, 0x81, 0xE2,
    0x00, 0x20, 0x91, 0xE5, 0x00, 0x60, 0x22, 0xE9, 0x02, 0xD0, 0xA0, 0xE1,
    0x30, 0xFF, 0x2F, 0xE1, 0x03, 0x00, 0xBD, 0xE8, 0x00, 0xD0, 0xA0, 0xE1,
    0x11, 0xFF, 0x2F, 0xE1 };

static void kernel_finalize_global_backdoor() {
  if (svc_handler_table_writable[SVC_BACKDOOR_NUM] == 0) {
    /* copy from waithax */
    u32 *free_space = EXC_VA_START;

    while(free_space[0] != 0xFFFFFFFF || free_space[1] != 0xFFFFFFFF)
      free_space++;
    u32 *free_space_writable = convertVAToPA(free_space) + AXIWRAMDSP_RW_MAPPING_OFFSET;

    /* write to writable portion */
    memcpy(free_space_writable, backdoor_code, sizeof(backdoor_code));
    svc_handler_table_writable[SVC_BACKDOOR_NUM] = free_space;

    flushEntireCaches();
  }
  svc_handler_table_writable[SEND_SYNC_REQUEST3] = svc_handler_table_writable[SVC_BACKDOOR_NUM];

  /* patch out svc acl check */
  *svc_acl_check_writable = 0xE3B0A001; // MOVS R10, #1
}

bool finalize_global_backdoor() {
  /* Currently the local backdoor really. This will make itself global :-) */
  svcGlobalBackdoor((s32(*)(void)) &kernel_finalize_global_backdoor);
  /* Check we didn't break things. */
  return global_backdoor_installed();
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
