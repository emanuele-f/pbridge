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
#include <sys/types.h>
#include <unistd.h>

#include "pbridge.h"

const int (*original_puts) (const char *);

const int my_puts(const char *str) {
  original_puts("this is from my_puts!!");
  return 0;
}

// Refs
// https://0x00sec.org/t/linux-internals-the-art-of-symbol-resolution/1488

int main() {
  pid_t mypid = getpid();
  printf("My PID: %d\n", mypid);

  char elf_path[256];
  pbridge_get_process_path(mypid, elf_path, sizeof(elf_path));
  printf("ELF Path: %s\n", elf_path);

  void *base_addr = pbridge_get_text_relocation_base_addr(mypid);
  printf(".text is located at %p\n", base_addr);

  void **puts_got_entry = (void **)((ulong)base_addr + (ulong)pbridge_find_got_symbol_addr(elf_path, "puts@GLIBC_"));
  printf("puts is located at address %p in .got table\n", puts_got_entry);

  original_puts = *puts_got_entry;
  printf("puts before linking: pointing to in %p .plt table", original_puts);

  // linking taking place
  puts("");

  original_puts = *((void**)puts_got_entry);
  printf("puts after linking: pointing to %p in libc\n", original_puts);
  original_puts("This message is from libc puts");

  printf("overwriting the puts pointer with our custom function at %p\n", my_puts);
  *puts_got_entry = my_puts;

  puts("This message will never be shown");
  return 0;
}
