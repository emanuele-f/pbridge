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

/* Environment API */
pbridge_env_t* pbridge_env_init(pid_t pid, size_t data_size);
int pbridge_env_destroy(pbridge_env_t *env);
void pbridge_env_load_reset_text(pbridge_env_t *env);
void* pbridge_env_malloc(pbridge_env_t *env, size_t size);
void pbridge_env_print(pbridge_env_t *env);
void pbridge_env_status(pbridge_env_t *env);
void pbridge_env_dump_registers(pbridge_env_t *env);
int pbridge_env_disassemble(pbridge_env_t *env, void*addr, size_t size);
void* pbridge_env_insert_payload(pbridge_env_t *env, void *payload, size_t payload_size);

/* Invocation API */
pbridge_pbridge_invok* pbridge_init_invocation(size_t stack_size);
void pbridge_destroy_invocation(pbridge_pbridge_invok *invok);
void* pbridge_env_load_invocation(pbridge_env_t *env, pbridge_pbridge_invok *invok, void *fnaddr);

/* Function API */
pbridge_function_t* pbridge_func_init(pbridge_env_t *env, void *fn_addr);
int pbridge_prepare_invocation(pbridge_function_t *func);
int pbridge_func_invoke(pbridge_function_t *func, long *rv);
void pbridge_func_destroy(pbridge_function_t *func);

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
/* next parameters are put on the stack. Caller must clean up the stack. Params can be modified. */

/* Breakpoints API */
int pbridge_env_set_breakpoint(pbridge_env_t *env, const void *target_addr);
int pbridge_env_del_breakpoint(pbridge_env_t *env, const void *target_addr);
int pbridge_env_clear_breakpoints(pbridge_env_t *env);
int pbridge_env_get_replaced_by_breakpoint(pbridge_env_t *env, const void *target_addr, u_int8_t *instr);
int pbridge_env_resolve_breakpoint(pbridge_env_t *env);

/* Misc API */
void* pbridge_env_resolve_static_symbol(pbridge_env_t *env, const char *sym_name, char sym_type);
void* pbridge_env_get_symbol_got_entry(pbridge_env_t *env, const char *sym_name);
int pbridge_env_dynamic_symbol_addr_rw(pbridge_env_t *env, const char *sym_name, const void *new_addr, void *old_addr);
void* pbridge_env_wait_trap(pbridge_env_t *env);

#endif
