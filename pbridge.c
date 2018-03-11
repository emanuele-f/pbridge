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

#include "includes.h"

// number of bytes in a JMP/CALL rel32 instruction
#define REL32_SZ 5
#define STACK_FOOTER_SZ (REL32_SZ + 1) // +trap instruction

#define CALL_REL32 0xe8
#define NOP 0x90
#define TRAP 0xcc

/* ******************************************************* */

/* Performs a call to mmap on ptrace */
static void* ptrace_call_mmap(pid_t pid, void *base_addr, size_t page_size,
            size_t data_size, const struct user_regs_struct *oldregs) {
  struct user_regs_struct newregs;

  void *rip = (void *)oldregs->rip;

  memcpy(&newregs, oldregs, sizeof(newregs));
  newregs.rax = 9;                           // mmap
  // note: we request a page near to the original text segment to work with rel jumps
  newregs.rdi = (long) (base_addr - getpagesize()); // addr
  newregs.rsi = page_size;                   // length
  newregs.rdx = PROT_READ | PROT_EXEC;       // prot
  newregs.r10 = MAP_PRIVATE | MAP_ANONYMOUS; // flags
  newregs.r8 = -1;                           // fd
  newregs.r9 = 0;                            // offset

  uint8_t old_word[8] = {0};
  uint8_t new_word[8] = {0};
  new_word[0] = 0x0f; // SYSCALL
  new_word[1] = 0x05; // SYSCALL
  new_word[2] = 0xff; // JMP %rax
  new_word[3] = 0xe0; // JMP %rax

  // insert the SYSCALL instruction into the process, and save the old word
  if (pbridge_rw_mem(pid, rip, new_word, old_word, sizeof(new_word))) {
    goto fail;
  }

  // set the new registers with our syscall arguments
  if (ptrace(PTRACE_SETREGS, pid, NULL, &newregs)) {
    perror("PTRACE_SETREGS");
    goto fail;
  }

  // invoke mmap(2)
  if (pbridge_singlestep(pid)) {
    goto fail;
  }

  // read the new register state, so we can see where the mmap went
  if (ptrace(PTRACE_GETREGS, pid, NULL, &newregs)) {
    perror("PTRACE_GETREGS");
    goto fail;
  }

  // this is the address of the memory we allocated
  void *mmap_memory = (void *)newregs.rax;
  if (mmap_memory == (void *)-1) {
    printf("failed to mmap\n");
    goto fail;
  }

#if 1
  // modify the jump to skip the data section
  newregs.rax = (long)((u_int8_t*)mmap_memory + data_size);
  if (ptrace(PTRACE_SETREGS, pid, NULL, &newregs)) {
    perror("PTRACE_SETREGS");
    goto fail;
  }

  // jump to mapped memory. this is needed in oder to execute the instructions that follow
  // without overwriting the existing process memory
  if (pbridge_singlestep(pid)) {
    goto fail;
  }

  if (ptrace(PTRACE_GETREGS, pid, NULL, &newregs)) {
    perror("PTRACE_GETREGS");
    goto fail;
  }

  if (newregs.rip != (long)((u_int8_t*)mmap_memory + data_size)) {
    printf("unexpectedly jumped to %p\n", (void *)newregs.rip);
    goto fail;
  }
#endif

  // restore old word
  pbridge_rw_mem(pid, rip, old_word, NULL, sizeof(old_word));
  return mmap_memory;

fail:
  pbridge_rw_mem(pid, rip, old_word, NULL, sizeof(old_word));
  return NULL;
}

/* ******************************************************* */

static int ptrace_call_unmap(pid_t pid, void *page_addr, size_t page_size, const struct user_regs_struct *oldregs) {
  struct user_regs_struct newregs;

  void *rip = (void *)oldregs->rip;

  memcpy(&newregs, oldregs, sizeof(newregs));

  uint8_t old_word[8] = {0};
  uint8_t new_word[8] = {0};
  new_word[0] = 0x0f; // SYSCALL
  new_word[1] = 0x05; // SYSCALL
  new_word[2] = 0xff; // JMP %rax
  new_word[3] = 0xe0; // JMP %rax

  // insert the SYSCALL instruction into the process, and save the old word
  if (pbridge_rw_mem(pid, rip, new_word, old_word, sizeof(new_word)))
    goto fail;

  newregs.rax = 11;                // munmap
  newregs.rdi = (long)page_addr;   // addr
  newregs.rsi = page_size;         // size
  if (ptrace(PTRACE_SETREGS, pid, NULL, &newregs)) {
    perror("PTRACE_SETREGS");
    goto fail;
  }

  // make the system call
  if (pbridge_singlestep(pid))
    goto fail;

  if (ptrace(PTRACE_GETREGS, pid, NULL, &newregs)) {
    perror("PTRACE_GETREGS");
    goto fail;
  }

  if(newregs.rax != 0) {
    perror("munmap error");
    goto fail;
  }

  // restore old word
  pbridge_rw_mem(pid, rip, old_word, NULL, sizeof(old_word));
  return 0;

fail:
  pbridge_rw_mem(pid, rip, old_word, NULL, sizeof(old_word));
  return -1;
}

/* ******************************************************* */

static int32_t compute_reljump_32(void *from, void *to) {
  int64_t delta = (int64_t)to - (int64_t)from - REL32_SZ;

  if (delta < INT_MIN || delta > INT_MAX) {
    printf("cannot do relative jump of size %li; did you compile with -fPIC?\n",
           delta);
    exit(1);
  }

  return (int32_t)delta;
}

/* ******************************************************* */

/* Initialize a ptrace environment */
int pbridge_env_init(pbridge_env_t *env, pid_t pid, size_t data_size) {
  const size_t page_size = getpagesize();
  memset(env, 0, sizeof(pbridge_env_t));

  if(data_size > page_size)
    return -1;

  if (ptrace(PTRACE_GETREGS, pid, NULL, &env->origin_regs)) {
    perror("PTRACE_GETREGS");
    return -1;
  }

  env->base_addr = pbridge_get_text_relocation_base_addr(pid);
  env->page_addr = ptrace_call_mmap(pid, env->base_addr, page_size, data_size, &env->origin_regs);

  if(!env->page_addr) return -1;

  printf("Mapped %lu B memory at %p\n", page_size, env->page_addr);

  if(! env->page_addr)
    return -1;

  env->pid = pid;
  env->tot_size = page_size;
  env->data_size = data_size;
  env->text_size = env->tot_size - env->data_size;

  return 0;
}

/* ******************************************************* */

int pbridge_env_destroy(pbridge_env_t *env) {
  // Got back on the main text page
  if (ptrace(PTRACE_SETREGS, env->pid, NULL, &env->origin_regs)) {
    perror("PTRACE_SETREGS");
    return -1;
  }

  ptrace_call_unmap(env->pid, env->page_addr, env->tot_size, &env->origin_regs);

  // Restore the registers after the unmap
  if (ptrace(PTRACE_SETREGS, env->pid, NULL, &env->origin_regs)) {
    perror("PTRACE_SETREGS");
    return -1;
  }

  return 0;
}

/* ******************************************************* */

pbridge_pbridge_invok* pbridge_init_invocation(size_t stack_size) {
  pbridge_pbridge_invok *invok = calloc(sizeof(pbridge_pbridge_invok), 1);

  if (stack_size % sizeof(void *) != 0) {
    printf("invalid len, not a multiple of %zd\n", sizeof(void *));
    return NULL;
  }

  if(!invok || stack_size < STACK_FOOTER_SZ) return NULL;

  invok->stack_size = stack_size;
  invok->stack = calloc(stack_size, 1);

  if(! invok->stack) {
    free(invok);
    return NULL;
  }

  // reserve space for the jump address
  invok->stack[invok->stack_size-STACK_FOOTER_SZ] = CALL_REL32;
  invok->stack[invok->stack_size-1] = TRAP;
  invok->cur_size += STACK_FOOTER_SZ;

  return invok;
}

/* ******************************************************* */

void pbridge_destroy_invocation(pbridge_pbridge_invok *invok) {
  free(invok->stack);
  free(invok);
}

/* ******************************************************* */

static void ptrace_invocation_align_8(pbridge_pbridge_invok *invok) {
  int padding = 8 - (invok->cur_size % 8);

  while(padding) {
    invok->stack[invok->stack_size - invok->cur_size - 1] = NOP;
    padding--;
    invok->cur_size++;
  }
}

/* ******************************************************* */

static void ptrace_invocation_set_jump_offset(pbridge_pbridge_invok *invok, u_int32_t jump_offset) {
  printf("RELJUMP: 0x%x\n", jump_offset);
  memcpy(&invok->stack[invok->stack_size-STACK_FOOTER_SZ+1], &jump_offset, REL32_SZ-1);
}

/* ******************************************************* */

int pbridge_env_disassemble(pbridge_env_t *env, void *addr, size_t size) {
  void *buffer = malloc(size);
  int rv = 0;

  if(! buffer) {
    perror("malloc");
    return -1;
  }

  if (pbridge_rw_mem(env->pid, addr, NULL, buffer, size))
    rv = -1;
  else
    rv = pbridge_disassemble(buffer, size);

  free(buffer);
  return rv;
}

/* ******************************************************* */

void* pbridge_env_insert_payload(pbridge_env_t *env, void *payload, size_t payload_size) {
  if(payload_size > pbridge_env_text_residual(env))
    return NULL;

  void *load_addr = pbridge_env_cur_text(env);

  // write the process memory
  if(pbridge_rw_mem(env->pid, load_addr, payload, NULL, payload_size))
    return NULL;

  env->text_used += payload_size;

  return load_addr;
}

/* ******************************************************* */

/* Insert the invocation in the callee process and returns its load address */
void* pbridge_env_load_invocation(pbridge_env_t *env, pbridge_pbridge_invok *invok, void *fnaddr) {
  ptrace_invocation_align_8(invok);

  if(invok->cur_size > pbridge_env_text_residual(env))
    return NULL;

  // calculate the jump offset relative the current text position
  u_int32_t jump_offset = compute_reljump_32(pbridge_env_cur_text(env), fnaddr);
  // add the additional stack contents to the offset
  jump_offset -= invok->cur_size - STACK_FOOTER_SZ;
  ptrace_invocation_set_jump_offset(invok, jump_offset);

  return pbridge_env_insert_payload(env, pbridge_invocation_get_stack(invok), invok->cur_size);
}

/* ******************************************************* */

/* Insert the invocation in the callee process */
int pbridge_env_perform_invocation(pbridge_env_t *env, pbridge_pbridge_invok *invok) {
  // we should stop here with the trap
  ptrace(PTRACE_CONT, env->pid, NULL, NULL);

  if (pbridge_wait_process("PTRACE_CONT"))
    return -1;

  return 0;
}

/* ******************************************************* */

void* pbridge_env_resolve_static_symbol(pbridge_env_t *env, const char *sym_name, char sym_type) {
  char elf_path[1024] = {0};

  if(pbridge_get_process_path(env->pid, elf_path, sizeof(elf_path)) == -1)
    return NULL;

  void *static_addr = pbridge_find_static_symbol_addr(elf_path, sym_name, sym_type);
  void *relocation_base = env->base_addr;

  if(!static_addr) return NULL;

  return (void *)((u_int64_t)relocation_base + (u_int64_t)static_addr);
}

/* ******************************************************* */

void* pbridge_env_get_symbol_got_entry(pbridge_env_t *env, const char *sym_name) {
  char elf_path[1024] = {0};

  if(pbridge_get_process_path(env->pid, elf_path, sizeof(elf_path)) == -1)
    return NULL;

  void *got_addr = pbridge_find_got_symbol_addr(elf_path, sym_name);
  void *relocation_base = env->base_addr;

  if(!got_addr) return NULL;

  return (void *)((u_int64_t)relocation_base + (u_int64_t)got_addr);
}

/* ******************************************************* */

/* useful for injection */
void* pbridge_env_overwrite_dynamic_symbol_addr(pbridge_env_t *env, const char *sym_name, void *new_addr) {
  void *got_addr = pbridge_env_get_symbol_got_entry(env, sym_name);
  if(!got_addr) return NULL;

  if(pbridge_rw_mem(env->pid, got_addr, &new_addr, NULL, sizeof(new_addr)) != 0)
    return NULL;

  return got_addr;
}

/* ******************************************************* */

void pbridge_env_load_reset_text(pbridge_env_t *env) {
  env->text_used = 0;
}

/* ******************************************************* */

void* pbridge_env_malloc(pbridge_env_t *env, size_t size) {
  if(size > pbridge_env_data_residual(env))
    return NULL;

  void *ptr = &env->page_addr[env->data_used];
  env->data_used += size;
  return ptr;
}

/* ******************************************************* */

pbridge_function_t* pbridge_init_function(pbridge_env_t *env, void *fn_addr) {
  pbridge_function_t *new_func;
  void *load_addr;

  if((new_func = (pbridge_function_t *)calloc(1, sizeof(pbridge_function_t))) == NULL) {
    perror("calloc");
    return NULL;
  }

  if (ptrace(PTRACE_GETREGS, env->pid, NULL, &new_func->working_regs)) {
    perror("PTRACE_GETREGS");
    free(new_func);
    return NULL;
  }

  //memcpy(new_func->working_regs, new_func->origin_regs, sizeof(*new_func->working_regs));

  // Configure the invocation
  new_func->invok = pbridge_init_invocation(64);
  if(! new_func->invok) {
    puts("cannot allocate invocation");
    free(new_func);
    return NULL;
  }

  if(! (load_addr = pbridge_env_load_invocation(env, new_func->invok, fn_addr))) {
    pbridge_destroy_invocation(new_func->invok);
    free(new_func);
    perror("pbridge_env_load_invocation");
    return NULL;
  }

  printf("Function loaded at address %p\n", load_addr);

  // Set the RIP to point to the load address
  new_func->working_regs.rip = (long)load_addr;
  new_func->env = env;

  return new_func;
}

/* ******************************************************* */

int pbridge_invoke_function(pbridge_function_t *func, long *rv) {
  struct user_regs_struct regs;

  // TODO + supporto both existing invocation and new invocation style call
  // TODO + consider the cost of a call to ptrace, and restructure accordingly

  if(ptrace(PTRACE_SETREGS, func->env->pid, NULL, &func->working_regs)) {
    perror("PTRACE_SETREGS");
    return -1;
  }

  if(pbridge_env_perform_invocation(func->env, func->invok) != 0) {
    //perror("pbridge_env_perform_invocation");
    return -1;
  }

  // Read rv
  if (ptrace(PTRACE_GETREGS, func->env->pid, NULL, &regs)) {
    perror("PTRACE_GETREGS");
    return -1;
  }

  if(rv) *rv = regs.rax;
  return 0;
}

/* ******************************************************* */

void pbridge_destroy_function(pbridge_function_t *func) {
  pbridge_destroy_invocation(func->invok);

  // TODO more finalization?
}

/* ******************************************************* */

void pbridge_env_print(pbridge_env_t *env) {
  size_t tot_used = env->text_used + env->data_used;

  printf("Env [%p ~ pid=%d, base=%p, @map=%p]\n"
    "  Size: %lu/%lu\n"
    "  TextSize: %lu/%lu\n"
    "  DataSize: %lu/%lu\n",
    env, env->pid, env->base_addr, env->page_addr,
    tot_used, env->tot_size,
    env->text_used, env->text_size,
    env->data_used, env->data_size);

  if(! tot_used) return;

  void *buf = malloc(max(env->text_used, env->data_used));
  if(!buf) return;

  if(env->data_used && (pbridge_rw_mem(env->pid, env->page_addr, NULL, buf, env->data_used) == 0)) {
    puts("  [DATA@map]");
    pbridge_hexdump(buf, env->data_used);
  }

  if(env->text_used && (pbridge_rw_mem(env->pid, pbridge_env_text_start(env), NULL, buf, env->text_used) == 0)) {
    puts("  [TEXT@map]");
    pbridge_disassemble(buf, env->text_used);
  }

  free(buf);
}

/* ******************************************************* */

void pbridge_env_dump_registers(pbridge_env_t *env) {
  struct user_regs_struct regs;

  if (ptrace(PTRACE_GETREGS, env->pid, NULL, &regs)) {
    perror("PTRACE_GETREGS");
    return;
  }

  pbridge_dump_registers(&regs);
}
