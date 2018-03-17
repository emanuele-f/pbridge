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

#ifndef min
#define min(x, y) ((x < y) ? (x) : (y))
#endif

#ifndef max
#define max(x, y) ((x > y) ? (x) : (y))
#endif

/* ********************************************************************* */
/* Process Control API */
/* ********************************************************************* */

/*
 * Wait for a traced process event to happen. Usually this event tells us that
 * the traced process has stopped and we have control again. [name] is just an
 * identifier used for logging.
 *
 * Return 0 on success.
 */
int pbridge_wait_process(const char *name);

/*
 * Perform a single step execution on the process.
 * Return 0 on success.
 */
int pbridge_singlestep(pid_t pid);

/*
 * Read and/or write process memory at [where] address of [len] bytes.
 *
 * If [new_text] is not NULL, [len] bytes will be copied from [new_text] in
 * tracee memory to [where] in traced process memory.
 *
 * If [old_text] is not NULL, [len] bytes will be copied from [where] in
 * traced process memory to [old_text] in tracee memory.
 *
 * Return 0 on success.
 */
int pbridge_rw_mem(pid_t pid, const void *where, const void *new_text, void *old_text,
            size_t len);

/*
 * Given the [pid] of process, execute the PTRACE_ATTACH on all of its child
 * threads, effectively freezing (pausing) the entire process.
 */
int pbridge_attach_all(pid_t pid);

/*
 * Given the [pid] of process, execute the PTRACE_DETACH on all of its child
 * threads, effectively de-freezing (continuing) the entire process.
 */
int pbridge_detach_all(pid_t pid);

/* ********************************************************************* */
/* Symbol Lookup API */
/* ********************************************************************* */

/*
 * Lookup the compile time symbol [sym_name] address of type [sym_type] into the [elf_path]
 * binary. The [sym_type] follows the nm linux command convention.
 *
 * Return the symbol offset address on success, NULL on error.
 */
void* pbridge_find_static_symbol_addr(const char *elf_path, const char *sym_name, char sym_type);

/*
 * Find the link time GOT entry of sumbol [sym_name].
 *
 * Return the symbol offset address on success, NULL on error.
 */
void* pbridge_find_got_symbol_addr(const char *elf_path, const char *sym_name);

/*
 * Find the runtime relocated base address of the [pid] process. This address
 * changes on every start of the program. All the static/dynamic symbols addresses
 * reported into the ELF binary are realtive to this base address.
 *
 * Return the relocated base address on success, NULL on error.
 */
void* pbridge_get_text_relocation_base_addr(pid_t pid);

/*
 * Get the full path of the [pid] process and store it into the [buf] of [bufsize]
 * bytes.
 *
 * Return 0 on success.
 */
int pbridge_get_process_path(pid_t pid, char *buf, size_t bufsize);

/* ********************************************************************* */
/* Dump Utils */
/* ********************************************************************* */

/*
 * Disassemble opcodes at [code] address into the current process space of
 * [code_size] bytes and print on screen. The [base_addr] can be used to print
 * the opcode offsets using this base_addr as a reference.
 *
 * Return 0 on success.
 */
int pbridge_disassemble(void *code, size_t code_size, void *base_addr);

/*
 * Hexdump a memory region into the current process space at [data] of [size]
 * bytes.
 */
void pbridge_hexdump(const void* data, size_t size);

/*
 * Dump the [regs] registers contents on screen in a gdb similar format.
 */
void pbridge_dump_registers(const struct user_regs_struct *regs);

#endif
