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

#ifndef _PBRIDGE_H_
#define _PBRIDGE_H_

#include "defines.h"
#include "utils.h"

/* ********************************************************************* */
/* Environment API - the main container for pbridge status. */
/* ********************************************************************* */

/*
 * Init pbridge environmnet and mmap a memory page in process memory.
 * The process identified by [pid] should be in a traced (ptrace attached) state.
 * 
 * Within the allocated page, a [data_size] bytes space will be reserved for custom
 * allocations (see pbridge_env_malloc), wherease the remaining part will be reserved
 * for actual instructions (see pbridge_env_insert_payload / pbridge_func_init).
 * 
 * Returns NULL on failure.
 */
pbridge_env_t* pbridge_env_init(pid_t pid, size_t data_size);

/*
 * Destroy and environmnet and unmap the previously allocated memory page.
 * The cpu registers will be restored to its original values they had before
 * pbridge_env_init.
 *
 * Returns 0 on success.
 */
int pbridge_env_destroy(pbridge_env_t *env);

/*
 * Allocates data into the reserved data space of [size] bytes into the pbridge
 * mmapped page.
 *
 * Returns NULL on failure; pointer in process space to allocated memory on success
 */
void* pbridge_env_malloc(pbridge_env_t *env, size_t size);

/*
 * Print infomration about the mmapped memory page. The data area will be printed
 * in hexdump while the textarea will be decompiled.
 */
void pbridge_env_print(pbridge_env_t *env);

/*
 * Print current registers contents and show disassembled instructions at rip
 * position.
 */
void pbridge_env_status(pbridge_env_t *env);

/*
 * Print current registers contents.
 */
void pbridge_env_dump_registers(pbridge_env_t *env);

/*
 * Disassemble [size] bytes instructions starting at [addr].
 *
 * Return 0 on success.
 */
int pbridge_env_disassemble(pbridge_env_t *env, void *addr, size_t size);

/*
 * Insert [payload_size] bytes [payload] instructions into the mmapped
 * instruction region. This is useful to inject custom functions.
 */
void* pbridge_env_insert_payload(pbridge_env_t *env, void *payload, size_t payload_size);

/* ********************************************************************* */
/* Function API - a wrapper to invoke functions in process memory */
/* ********************************************************************* */

/*
 * Initialize a new function structure. [fn_addr] is the address of the function
 * in process space we would like to call.
 *
 * Return NULL on failure.
 */
pbridge_function_t* pbridge_func_init(pbridge_env_t *env, void *fn_addr);

/*
 * Setup the processor state for function invocation. Usually you would:
 *  1) Init a function wrapper with pbridge_func_init
 *  2) Modify the pbridge_function_t working_regs registers with custom parameters
 *  3) Call pbridge_prepare_invocation to set the registers
 *  4) Call pbridge_func_invoke to perform the actual invocation of the function
 *  5) Call pbridge_func_destroy when it's not needed anymore.
 *
 * Return 0 on success.
 */
int pbridge_prepare_invocation(pbridge_function_t *func);

/*
 * Invoke the function specified by the [func] wrapper and wait for the
 * invocation to terminate. The function return value will be stored into the
 * [rv] variable.
 *
 * Return 0 on success.
 */
int pbridge_func_invoke(pbridge_function_t *func, long *rv);

/*
 * Destroy a function wrapper.
 */
void pbridge_func_destroy(pbridge_function_t *func);


/* ********************************************************************* */
/* Function parameters helper macros. */
/* ********************************************************************* */
#define pbridge_ret_val(regs) regs.rax
#define pbridge_param_1(regs) regs.rdi
#define pbridge_param_2(regs) regs.rsi
#define pbridge_param_3(regs) regs.rdx
#define pbridge_param_4(regs) regs.rcx
#define pbridge_param_5(regs) regs.r8
#define pbridge_param_6(regs) regs.r9

#define pbridge_func_set_param_1(func, val) pbridge_param_1(func->working_regs) = (long)val
#define pbridge_func_set_param_2(func, val) pbridge_param_2(func->working_regs) = (long)val
#define pbridge_func_set_param_3(func, val) pbridge_param_3(func->working_regs) = (long)val
#define pbridge_func_set_param_4(func, val) pbridge_param_4(func->working_regs) = (long)val
#define pbridge_func_set_param_5(func, val) pbridge_param_5(func->working_regs) = (long)val
#define pbridge_func_set_param_6(func, val) pbridge_param_6(func->working_regs) = (long)val

/* NOTE: next parameters are put on the stack. Caller must clean up the stack. Params can be modified. */

/* ********************************************************************* */
/* Breakpoints API */
/* ********************************************************************* */

/*
 * Sets up a breakpoint at [target_addr] in process memory. The breakpoint causes
 * the original instruction located at [target_addr] to be replaced with a TRAP
 * instruction. After reaching the breakpoint, you have to call
 * pbridge_env_resolve_breakpoint in order to execute the original instruction.
 *
 * Return 0 on success.
 */
int pbridge_env_set_breakpoint(pbridge_env_t *env, const void *target_addr);

/*
 * Delete a previously set breakpoint at [target_addr] in process memory.
 * The TRAP will be removed and the original opcode restored.
 *
 * Return 0 on success.
 */
int pbridge_env_del_breakpoint(pbridge_env_t *env, const void *target_addr);

/*
 * Delete all previously set breakpoints in process memory.
 * The TRAPs will be removed and the original opcodes restored.
 *
 * Return 0 on success.
 */
int pbridge_env_clear_breakpoints(pbridge_env_t *env);

/*
 * Fetch the original opcode which was replaced by a TRAP instruction at
 * [target_addr] address after a pbridge_env_set_breakpoint and store into [instr].
 *
 * Return 0 on success.
 */
int pbridge_env_get_replaced_by_breakpoint(pbridge_env_t *env, const void *target_addr, u_int8_t *instr);

/*
 * This can only be used after reaching a TRAP instruction insterted by a pbridge_env_set_breakpoint.
 * This executes the original instruction in order to preserve the original code logic and possibly
 * continue the execution.
 *
 * Return 0 on success.
 */
int pbridge_env_resolve_breakpoint(pbridge_env_t *env);

/* ********************************************************************* */
/* Misc API */
/* ********************************************************************* */

/*
 * Resolve the compile time symbol [sym_name] (located into the ELF) address in
 * process memory. The [sym_type] specifies the type of the symbol to resolve
 * and it follows the nm linux command convention.
 *
 * Return NULL on error; a pointer to the process space symbol address on success.
 */
void* pbridge_env_resolve_static_symbol(pbridge_env_t *env, const char *sym_name, char sym_type);

/*
 * Resolve the link time symbol [sym_name] address into the GOT table entry.
 * This address contains either a pointer to the actual resolved [sym_name] address
 * or a pointer to a linker stub to resolve the symbol. You can replace this address
 * with the address of another function to perform function hijacking.
 * See pbridge_env_dynamic_symbol_addr_rw for an helper function to do this.
 *
 * Return NULL on error; a pointer to the process space symbol address on success.
 */
void* pbridge_env_get_symbol_got_entry(pbridge_env_t *env, const char *sym_name);

/* 
 * Reads/Replaces with a custom address the link time symbol [sym_name] address into
 * the GOT table entry.
 *
 * If [new_addr] is specified, then the dynamic symbol will now be hijacked to this address.
 * If [old_addr] is specified, then the old symbol address will be stored into  [old_addr].
 *
 * Return 0 on success.
 */
int pbridge_env_dynamic_symbol_addr_rw(pbridge_env_t *env, const char *sym_name, const void *new_addr, void *old_addr);

/*
 * Continues the traced process and waits for a TRAP instruction to give us
 * the control again.
 * The return value is useful to check which breakpoint we just reached.
 *
 * Return NULL on failure, the address of the TRAP instrunction on success.
 */
void* pbridge_env_wait_trap(pbridge_env_t *env);

#endif
