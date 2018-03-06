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
int pbridge_env_init(pbridge_env_t *env, pid_t pid, size_t data_size);
void pbridge_env_destroy(pbridge_env_t *env);
void pbridge_env_load_reset_text(pbridge_env_t *env);
void* pbridge_env_malloc(pbridge_env_t *env, size_t size);

/* Invocation API */
pbridge_pbridge_invok* pbridge_init_invocation(size_t stack_size);
void pbridge_destroy_invocation(pbridge_pbridge_invok *invok);
void* pbridge_env_load_invocation(pbridge_env_t *env, pbridge_pbridge_invok *invok, void *fnaddr);
int pbridge_env_perform_invocation(pbridge_env_t *env, pbridge_pbridge_invok *invok);

/* Function API */
pbridge_function_t_t* pbridge_init_function(pbridge_env_t *env, void *fn_addr);
long pbridge_invoke_function(pbridge_function_t_t *func);
void pbridge_destroy_function(pbridge_function_t_t *func);

/* Misc API */
void* pbridge_env_resolve_symbol_addr(pbridge_env_t *env, const char *sym_name, char sym_type);

#endif
