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

typedef struct callme_function {
  pbridge_function_t *base;

  void *message_buf;
} callme_function_t;

static pbridge_env_t *prog_env;
static callme_function_t callme_def;

#define CALLME_STRING_BUF_SIZE 128

/* ******************************************************* */

static int setup_callme(void *fn_addr) {
  callme_def.base = pbridge_func_init(prog_env, fn_addr);
  if(! callme_def.base) return -1;

  pbridge_func_set_param_1(callme_def.base, callme_def.message_buf);

  return 0;
}

static void finalize_callme() {
  pbridge_func_destroy(callme_def.base);
}

/* ******************************************************* */

static int callme(const void *message) {
  // Write message into process memory
  pbridge_rw_mem(prog_env->pid, callme_def.message_buf, message, NULL, min(CALLME_STRING_BUF_SIZE, strlen(message)+1));

  long rv = 0;

  pbridge_func_invoke(callme_def.base, &rv);
  return (int)rv;
}

/* ******************************************************* */

static void terminate_process(pid_t pid) {
  // kill the process, as we don't clean the environment and it will crash
  kill(pid, SIGTERM);
}

/* ******************************************************* */

int main(int argc, char **argv) {
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
  if(!(prog_env = pbridge_env_init(pid, 512))) {
    terminate_process(pid);
    return -1;
  }

  callme_def.message_buf = pbridge_env_malloc(prog_env, CALLME_STRING_BUF_SIZE);
  printf("Allocated a %d bytes buffer at %p\n", CALLME_STRING_BUF_SIZE, callme_def.message_buf);

  void *fn_addr = pbridge_env_resolve_static_symbol(prog_env, "callme", 'T');
  if(! fn_addr) {
    puts("Cannot get callme address");
    terminate_process(pid);
    return -1;
  }

  printf("Callme is at %p in process memory\n", fn_addr);

  if(setup_callme(fn_addr) != 0) return -1;

  printf("Got %d\n", callme("Ciao"));
  printf("Got %d\n", callme("Zio"));
  printf("Got %d\n", callme("Zia"));

  finalize_callme();

  pbridge_env_destroy(prog_env);

  /* *** */
  if (pbridge_detach_all(pid)) {
    perror("PTRACE_DETACH");
    return -1;
  }

  //terminate_process(pid);
  return 0;
}
