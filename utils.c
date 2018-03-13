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

#include <inttypes.h>
#include <capstone/capstone.h>

#include <dirent.h>

/* ******************************************************* */

void* pbridge_find_static_symbol_addr(const char *elf_path, const char *sym_name, char sym_type) {
  void *addr = NULL;

  char *cmd = calloc(1, strlen(elf_path) + 4); // nm cmd + NULL
  if(!cmd) {
    perror("calloc");
    return NULL;
  }

  char *lookup = calloc(1, strlen(sym_name) + 5); // lookup string + NULL
  if(!lookup) {
    perror("calloc");
    free(cmd);
    return NULL;
  }

  sprintf(cmd, "nm %s", elf_path);
  sprintf(lookup, " %c %s\n", sym_type, sym_name);

  FILE *f = popen(cmd, "r");

  if(f) {
    char line[256];

    while(! feof(f)) {
      if(fgets(line, sizeof(line), f) && strstr(line, lookup) && (strlen(line) > 20)) {
        line[16] = '\0';

        errno = 0;
        addr = (void *) strtoll(line, NULL, 16);
        if(errno == ERANGE) addr = 0;
        break;
      }
    }

    pclose(f);
  } else
    perror("pbridge_find_static_symbol_addr popen");

  free(cmd);
  free(lookup);
  return addr;
}

/* ******************************************************* */

void* pbridge_find_got_symbol_addr(const char *elf_path, const char *sym_name) {
  void *addr = NULL;

  char *cmd = calloc(1, strlen(elf_path) + 12); // objdump cmd + NULL
  if(!cmd) {
    perror("calloc");
    return NULL;
  }

  char *lookup = calloc(1, strlen(sym_name) + 22); // lookup string + NULL
  if(!lookup) {
    perror("calloc");
    free(cmd);
    return NULL;
  }

  // ensure exact match
  if(! strchr(sym_name, '@')) {
    printf("symbol %s must contain a reference to a dynamic library e.g. %s@GLIBC\n", sym_name, sym_name);
    return NULL;
  }

  sprintf(cmd, "objdump -R %s", elf_path);
  sprintf(lookup, " R_X86_64_JUMP_SLOT  %s", sym_name);

  FILE *f = popen(cmd, "r");

  if(f) {
    char line[256];

    while(! feof(f)) {
      if(fgets(line, sizeof(line), f) && strstr(line, lookup) && (strlen(line) > 22)) {
        line[16] = '\0';

        errno = 0;
        addr = (void *) strtoll(line, NULL, 16);
        if(errno == ERANGE) {
          printf("Address '%s' is out of range\n", line);
          addr = 0;
        }
        break;
      }
    }

    pclose(f);
  } else
    perror("pbridge_find_got_symbol_addr popen");

  free(cmd);
  free(lookup);
  return addr;
}

/* ******************************************************* */

/*
 * From https://github.com/eklitzke/ptrace-call-userspace
 *
 * Read/Write a process memory.
 *
 * where: process memory start address
 * new_text: if not NULL, new data to write
 * old_text: if not NULL, will contain the data read
 * len: number of bytes to write.
 *
 * NOTE: both *where* and *len* parameters should be aligned to a 64bit bound.
 * This is not enforced by the code, but a misaligned address may cause a segfault
 * in the rare case when the write appears at the bound of the memory pages space
 * allocated for the process.
 */
int pbridge_rw_mem(pid_t pid, const void *where, const void *new_text, void *old_text,
              size_t len) {
  long peek_data, poke_data;
  size_t blocksize = sizeof(poke_data);
  int last_unaligned_block;

  for (size_t copied = 0; copied < len; copied += blocksize) {
    last_unaligned_block = blocksize > len-copied;
    blocksize = min(blocksize, len-copied);

    if(new_text)
      memmove(&poke_data, new_text + copied, blocksize);

    if (old_text || last_unaligned_block) {
      errno = 0;
      peek_data = ptrace(PTRACE_PEEKTEXT, pid, where + copied, NULL);

      if (peek_data == -1 && errno) {
        perror("PTRACE_PEEKTEXT");
        return -1;
      }

      if(old_text)
        memmove(old_text + copied, &peek_data, blocksize);
    }

    if(new_text) {
      if(last_unaligned_block) {
        // this is the last block, and it is unaligned. We must avoid
        // overwriting the data next to it. We use the peek_data read before
        int offset = len % sizeof(poke_data);
        int to_keep = sizeof(poke_data) - offset;

        memmove(((u_int8_t *) &poke_data) + offset, ((u_int8_t *) &peek_data) + offset, to_keep);
      }

      if (ptrace(PTRACE_POKETEXT, pid, where + copied, (void *)poke_data) < 0) {
        perror("PTRACE_POKETEXT");
        return -1;
      }
    }
  }

  return 0;
}

/* ******************************************************* */

//
// From https://github.com/eklitzke/ptrace-call-userspace
//
int pbridge_wait_process(const char *name) {
  int status;
  if (wait(&status) == -1) {
    perror("wait");
    return -1;
  }
  if (WIFSTOPPED(status)) {
    if (WSTOPSIG(status) == SIGTRAP) {
      return 0;
    }
    printf("%s unexpectedly got status %s\n", name, strsignal(status));
    return -1;
  }
  printf("%s got unexpected status %d\n", name, status);
  return -1;
}

/* ******************************************************* */

//
// From https://github.com/eklitzke/ptrace-call-userspace
//
int pbridge_singlestep(pid_t pid) {
  if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL)) {
    perror("PTRACE_SINGLESTEP");
    return -1;
  }
  return pbridge_wait_process("PTRACE_SINGLESTEP");
}

/* ******************************************************* */

// assumption: the first region with r-xp is the base
void* pbridge_get_text_relocation_base_addr(pid_t pid) {
  char proc_path[32];
  void *addr = NULL;

  snprintf(proc_path, sizeof(proc_path), "/proc/%d/maps", pid);

  FILE *f = fopen(proc_path, "r");
  if(! f) return NULL;

  while(! feof(f)) {
    char line[512];

    if(fgets(line, sizeof(line), f) && strstr(line, " r-xp ") && (strlen(line) > 32)) {
      char *delim = strchr(line, '-');

      if(delim) {
        *delim = '\0';

        errno = 0;
        addr = (void *) strtoll(line, NULL, 16);
        if(errno == ERANGE) addr = 0;
        break;
      }
    }
  }

  fclose(f);

  return addr;
}

/* ******************************************************* */

int pbridge_get_process_path(pid_t pid, char *buf, size_t bufsize) {
  char proc_path[32];

  if(! bufsize) return -1;

  snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", pid);

  if(readlink(proc_path, buf, bufsize) != -1) {
    buf[bufsize-1] = '\0';

    const char strip_string[] = " (deleted)";
    char *found;

    // possibly remove ending (deleted) string
    if((found = strstr(buf, strip_string)) && (found + sizeof(strip_string)-1 == buf + strlen(buf)))
      *found = '\0';

    return 0;
  }

  return -1;
}

/* ******************************************************* */

// callback: return 0 on success, other on error (stops iteration)
static int foreach_thread_in_process(pid_t pid, int (callback) (pid_t tid)) {
  char proc_tasks[32];
  DIR *dir;
  struct dirent *dirent;
  int rv;

  snprintf(proc_tasks, sizeof(proc_tasks), "/proc/%d/task", pid);

  if((dir = opendir(proc_tasks))) {
    while((dirent = readdir(dir))) {
      if(dirent->d_name[0] != '.') {
        errno = 0;
        int tid = (int) strtol(dirent->d_name, NULL, 10);

        if(!errno) {
          if((rv = callback(tid)))
          break;
        }
      }
    }

    closedir(dir);
  } else {
    perror("opendir");
    rv = -1;
  }

  return rv;
}

static int thread_attach_callback(pid_t tid) {
  if(ptrace(PTRACE_ATTACH, tid, NULL, NULL)) {
    perror("attach");
    return -1;
  }

  // wait for the thread to actually stop
  if (waitpid(tid, 0, WSTOPPED) == -1) {
    perror("wait");
    return -1;
  }

  return 0;
}

int pbridge_attach_all(pid_t pid) {
  return foreach_thread_in_process(pid, thread_attach_callback);
}

static int thread_detach_callback(pid_t tid) {
  return ptrace(PTRACE_DETACH, tid, NULL, NULL);
}

int pbridge_detach_all(pid_t pid) {
  return foreach_thread_in_process(pid, thread_detach_callback);
}

/* ******************************************************* */

// https://gist.github.com/ccbrown/9722406
void pbridge_hexdump(const void* data, size_t size) {
  char ascii[17];
  size_t i, j;
  ascii[16] = '\0';
  for (i = 0; i < size; ++i) {
    printf("%02X ", ((unsigned char*)data)[i]);
    if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
      ascii[i % 16] = ((unsigned char*)data)[i];
    } else {
      ascii[i % 16] = '.';
    }
    if ((i+1) % 8 == 0 || i+1 == size) {
      printf(" ");
      if ((i+1) % 16 == 0) {
        printf("|  %s \n", ascii);
      } else if (i+1 == size) {
        ascii[(i+1) % 16] = '\0';
        if ((i+1) % 16 <= 8) {
          printf(" ");
        }
        for (j = (i+1) % 16; j < 16; ++j) {
          printf("   ");
        }
        printf("|  %s \n", ascii);
      }
    }
  }
}

/* ******************************************************* */

int pbridge_disassemble(void *code, size_t code_size, void *base_addr) {
  csh handle;
  cs_insn *insn;

  size_t count;

  if(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    return -1;

  count = cs_disasm(handle, code, code_size, 0, 0, &insn);

  if (count > 0) {
    size_t j;

    for (j = 0; j < count; j++)
      printf("0x%"PRIx64":\t%s\t\t%s\n", (ulong)base_addr + insn[j].address, insn[j].mnemonic, insn[j].op_str);

    cs_free(insn, count);
  } else
    printf("ERROR: Failed to disassemble given code!\n");

  cs_close(&handle);
  return 0;
}

/* ******************************************************* */

//#define REGISTER_LONG_DUMP

void pbridge_dump_registers(const struct user_regs_struct *regs) {
  printf("[Registers at %p]\n"
    " rax            0x%llx %llu\n"
    " rbx            0x%llx %llu\n"
    " rcx            0x%llx %llu\n"
    " rdx            0x%llx %llu\n"
    " rsi            0x%llx %llu\n"
    " rdi            0x%llx %llu\n"
    " rbp            0x%llx %llu\n"
    " rsp            0x%llx %llu\n"
    " r8             0x%llx %llu\n"
    " r9             0x%llx %llu\n"
    " r10            0x%llx %llu\n"
    " r11            0x%llx %llu\n"
    " r12            0x%llx %llu\n"
    " r13            0x%llx %llu\n"
    " r14            0x%llx %llu\n"
    " r15            0x%llx %llu\n"
    " rip            0x%llx %llu\n"
#ifdef REGISTER_LONG_DUMP
    " eflags         0x%llx %llu\n"
    " cs             0x%llx %llu\n"
    " ss             0x%llx %llu\n"
    " ds             0x%llx %llu\n"
    " es             0x%llx %llu\n"
    " fs             0x%llx %llu\n"
    " gs             0x%llx %llu\n"
    " fs_base        0x%llx %llu\n"
    " gs_base        0x%llx %llu\n"
#endif
    , regs,
    regs->rax, regs->rax, regs->rbx, regs->rbx,
    regs->rcx, regs->rcx, regs->rdx, regs->rdx,
    regs->rsi, regs->rsi, regs->rdi, regs->rdi,
    regs->rbp, regs->rbp, regs->rsp, regs->rsp, regs->r8, regs->r8,
    regs->r9, regs->r9, regs->r10, regs->r10,
    regs->r11, regs->r11, regs->r12, regs->r12,
    regs->r13, regs->r13, regs->r14, regs->r14,
    regs->r15, regs->r15, regs->rip, regs->rip
#ifdef REGISTER_LONG_DUMP
    , regs->eflags, regs->eflags, regs->cs, regs->cs,
    regs->ss, regs->ss, regs->ds, regs->ds,
    regs->es, regs->es, regs->fs, regs->fs, regs->gs, regs->gs,
    regs->fs_base, regs->fs_base, regs->gs_base, regs->gs_base
#endif
  );
}
