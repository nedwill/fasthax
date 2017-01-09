/* 3ds fasthax kernel exploit
 * 11.2 USA N3DS
 * Ned Williamson 2016
 */

#include <3ds.h>
#include <stdio.h>

#include "util.h"
#include "exploit.h"

int main() {
  gfxInitDefault();

  PrintConsole *print_console = consoleInit(GFX_TOP, NULL);
  consoleSelect(print_console);

  gspWaitForVBlank();

  if (k11_exploit()) {
    printf("[+] k11_exploit succeeded!\n");
  } else {
    printf("[-] k11_exploit failed!\n");
  }

  wait_for_user();

  gfxExit();
  return 0;
}
