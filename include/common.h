#ifndef __COMMON_H
#define __COMMON_H

#define CURRENT_KTHREAD 0xFFFF9000
#define CURRENT_PROCESS 0xFFFF9004

typedef struct version_table {
  u32 kver;
  u32 handle_lookup;
  u32 random_stub;
  u32 svc_handler_table;
  u32 svc_acl_check;
  u32 ktimer_pool_head;
  u32 ktimer_pool_size;
  u32 ktimer_base_offset;
} version_table;

extern version_table *table;

#endif
