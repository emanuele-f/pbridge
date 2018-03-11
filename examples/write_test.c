#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <assert.h>

#include "pbridge.h"
#include "includes.h"

int main(int argc, char **argv) {
  if(argc < 2) {
    printf("Usage: %s pid\n", basename(argv[0]));
    exit(1);
  }

  pid_t pid = atoi(argv[1]);

  if (pbridge_attach_all(pid)) {
    perror("PTRACE_ATTACH");
    return -1;
  }

  /* *** */
  struct user_regs_struct regs;
  if (ptrace(PTRACE_GETREGS, pid, NULL, &regs)) {
    perror("PTRACE_GETREGS");
    return -1;
  }

  #define NEW_TEXT_SIZE 5
  #define TEXT_VERIFY_SIZE 15
  char old_text[TEXT_VERIFY_SIZE];
  char new_text[TEXT_VERIFY_SIZE] = "\x01\x02\x03\x04\x05";

  pbridge_rw_mem(pid, (void *)regs.rip, NULL, old_text, TEXT_VERIFY_SIZE);
  puts("Before:");
  pbridge_hexdump(old_text, 10);

  pbridge_rw_mem(pid, (void *)regs.rip, new_text, NULL, NEW_TEXT_SIZE);
  pbridge_rw_mem(pid, (void *)regs.rip, old_text, NULL, NEW_TEXT_SIZE);

  pbridge_rw_mem(pid, (void *)regs.rip, NULL, new_text, TEXT_VERIFY_SIZE);
  puts("After:");
  pbridge_hexdump(new_text, 10);

  // They must be equal
  assert(memcmp(new_text, old_text, TEXT_VERIFY_SIZE) == 0);

  /* *** */

  if (pbridge_detach_all(pid)) {
    perror("PTRACE_DETACH");
    return -1;
  }

  puts("SUCCESS");
  return 0;
}
