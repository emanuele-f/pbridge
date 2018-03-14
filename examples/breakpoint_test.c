/*
 * pbridge                                           (C) 2018 Emanuele Faranda
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <libgen.h>

#include "pbridge.h"

#define FN_NAME "sleep@GLIBC_"
#define MEM_TO_CHECK_SIZE 20

int main(int argc, char **argv) {
  pbridge_env_t *prog_env;
  void *fn_addr;
  u_int8_t mem_before[MEM_TO_CHECK_SIZE];
  u_int8_t mem_after[MEM_TO_CHECK_SIZE];

  if(argc < 2) {
    printf("Usage: %s pid\n", basename(argv[0]));
    exit(1);
  }

  pid_t pid = atoi(argv[1]);

  // attach
  if (pbridge_attach_all(pid)) {
    perror("PTRACE_ATTACH");
    return -1;
  }

  /* *** */

  if(!(prog_env = pbridge_env_init(pid, 128))) {
    puts("Env init error");
    return -1;
  }

  printf("Attached to process %d\n", pid);

  if(pbridge_env_dynamic_symbol_addr_rw(prog_env, FN_NAME, NULL, &fn_addr)) {
    puts("Cannot get function '" FN_NAME "' address");
    return -1;
  }

  if(pbridge_rw_mem(pid, fn_addr, NULL, mem_before, MEM_TO_CHECK_SIZE)) {
    puts("pbridge_rw_mem read error");
    return -1; 
  }
  pbridge_env_disassemble(prog_env, fn_addr, MEM_TO_CHECK_SIZE);

  if(pbridge_env_set_breakpoint(prog_env, fn_addr)) {
    puts("Unable to set breakpoint");
    return -1;
  }
  printf("\nAdded breakpoint for " FN_NAME " at %p\n", fn_addr);

  pbridge_env_disassemble(prog_env, fn_addr, MEM_TO_CHECK_SIZE);

  for(int i=0; i<3; i++) {
    puts("\nWaiting for the breakpoint to trigger...");
    while(pbridge_env_wait_trap(prog_env) != fn_addr) puts("waiting...");

    puts("Breakpoint hit! Executing the actual code");
    if(pbridge_env_resolve_breakpoint(prog_env)) {
      puts("Could not resolve the breakpoint");
      return -1;
    }
  }

  puts("Removing the breakpoint");

  if(pbridge_env_del_breakpoint(prog_env, fn_addr)) {
    puts("Unable to remove the breakpoint");
    return -1; 
  }

  if(pbridge_rw_mem(pid, fn_addr, NULL, mem_after, MEM_TO_CHECK_SIZE)) {
    puts("pbridge_rw_mem read error");
    return -1; 
  }
  pbridge_env_disassemble(prog_env, fn_addr, MEM_TO_CHECK_SIZE);

  if(memcmp(mem_before, mem_after, MEM_TO_CHECK_SIZE)) {
    puts("Error: memory differs!");
    return -1;
  }

  /* *** */

  puts("\nDetatching from process...");
  pbridge_env_destroy(prog_env);

  if (pbridge_detach_all(pid)) {
    perror("PTRACE_DETACH");
    return -1;
  }

  return 0;
}
