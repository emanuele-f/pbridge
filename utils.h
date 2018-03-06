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

#ifndef _UTILS_H_
#define _UTILS_H_

#define min(x, y) ((x < y) ? (x) : (y))

void* find_symbol_static_addr(const char *elf_path, const char *sym_name, char sym_type);
int ptrace_poke_text(pid_t pid, const void *where, const void *new_text, void *old_text,
            size_t len);
int pbridge_wait_process(const char *name);
int pbridge_singlestep(pid_t pid);
void* pbridge_get_text_relocation_base_addr(pid_t pid);
int pbridge_get_process_path(pid_t pid, char *buf, size_t bufsize);

#endif
