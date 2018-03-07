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

// Do not worry about alignment for now -> this is a bug, may overflow
#define SKIP_ALIGNMENT_CHECK

/* ******************************************************* */

void* pbridge_find_static_addr(const char *elf_path, const char *sym_name, char sym_type) {
  void *addr = NULL;
  char *cmd = calloc(strlen(elf_path) + 4, 1);
  char *lookup = calloc(strlen(sym_name) + 5, 1);
  if(! cmd) return NULL;

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
  }

  free(cmd);
  return addr;
}

/* ******************************************************* */

//
// From https://github.com/eklitzke/ptrace-call-userspace
//
// Update the text area of pid at the area starting at where. The data copied
// should be in the new_text buffer whose size is given by len. If old_text is
// not null, the original text data will be copied into it. Therefore old_text
// must have the same size as new_text.
int pbridge_rw_mem(pid_t pid, const void *where, const void *new_text, void *old_text,
              size_t len) {
#ifndef SKIP_ALIGNMENT_CHECK
  if (len % sizeof(void *) != 0) {
    printf("invalid len, not a multiple of %zd\n", sizeof(void *));
    return -1;
  }
#endif

  long poke_data;
  for (size_t copied = 0; copied < len; copied += sizeof(poke_data)) {
    if(new_text) memmove(&poke_data, new_text + copied, sizeof(poke_data));

    if (old_text != NULL) {
      errno = 0;
      long peek_data = ptrace(PTRACE_PEEKTEXT, pid, where + copied, NULL);
      if (peek_data == -1 && errno) {
        perror("PTRACE_PEEKTEXT");
        return -1;
      }
      memmove(old_text + copied, &peek_data, sizeof(peek_data));
    }

    if(new_text) {
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
    return 0;
  }

  return -1;
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
