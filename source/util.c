#include <stdio.h>
#include <3ds.h>
#include "util.h"

static int user_interrupted() {
  hidScanInput();
  return hidKeysDown() & KEY_START;
}

void wait_for_user() {
  printf("waiting for user... press <start> to continue\n");
  while (!user_interrupted());
  svcSleepThread(1000000);
}
