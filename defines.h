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

#ifndef _DEFINES_H_
#define _DEFINES_H_

typedef struct pbridge_env {
  size_t tot_size;
  size_t text_size;
  size_t text_used;
  size_t data_size;
  size_t data_used;

  int pid;

  /* Status */
  u_char* invok_start;

  /* In tracee process memory */
  void *base_addr; // relocated base address
  u_char* page_addr; // mmapped memory
} pbridge_env_t;

/* In main process memory */
typedef struct pbridge_invok {
  size_t stack_size;
  size_t cur_size;
  u_char *stack;
} pbridge_pbridge_invok;

typedef struct pbridge_function_t {
  //struct user_regs_struct origin_regs;
  struct user_regs_struct working_regs;
  pbridge_pbridge_invok *invok;
  pbridge_env_t *env;
} pbridge_function_t_t;

inline size_t pbridge_env_text_residual(pbridge_env_t *env) {return env->text_size - env->text_used; }
inline size_t pbridge_env_data_residual(pbridge_env_t *env) {return env->data_size - env->data_used; }
inline u_int8_t* pbridge_env_text_start(pbridge_env_t *env) { return &env->page_addr[env->data_size]; }
inline u_int8_t* pbridge_env_cur_text(pbridge_env_t *env) { return &env->page_addr[env->data_size + env->text_used]; }

inline u_int8_t* pbridge_invocation_get_stack(pbridge_pbridge_invok *invok) { return &invok->stack[invok->stack_size - invok->cur_size]; }

#endif
