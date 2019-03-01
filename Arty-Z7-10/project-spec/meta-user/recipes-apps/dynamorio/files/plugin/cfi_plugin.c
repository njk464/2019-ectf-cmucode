/* **********************************************************
 * Copyright (c) 2014 Google, Inc.  All rights reserved.
 * Copyright (c) 2008 VMware, Inc.  All rights reserved.
 * **********************************************************/

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of VMware, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include "dr_api.h"
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>

/***** DEFINES *****/

#undef report_dynamorio_problem
#undef report_app_problem

#ifdef DEBUG
#define DPRINT(format,...)  (dr_fprintf(STDOUT, format, ##__VA_ARGS__))
#else
#define DPRINT(format,...)
#endif

#define DERR(format,...)

#define IMP(bb, w, i)       (instrlist_meta_preinsert((bb), (w), (i)))
#define OCR(r)              (opnd_create_reg((r)))
#define OUI(i, sz)          (opnd_create_immed_uint((i), (sz)))
#define OBD(b, i, s, d, sz) (opnd_create_base_disp((b), (i), (s), (d), (sz)))

#define MAX_SIGHANDLERS 64
#define MAX_SHADOW_SIZE 4096

/***** STATIC GLOBALS AND STRUCTS *****/

static bool found_main = false;
static bool run_main = false;
static app_pc main_entry = NULL;

static bool found_restore_core_regs = false;

static app_pc handlers[MAX_SIGHANDLERS];
static void *handlers_lock;

static uint counter = 3000;
static bool log_begin = false;

struct frame
{
    uint lr;
    uint sp;
    uint saved;
    uint persist;
};

struct thread_info
{
    uint shadow_count;
    struct frame shadow_stack[MAX_SHADOW_SIZE];
};

/***** SYSCALL FILTER *****/

static bool
syscall_check(int sysnum)
{
    return (sysnum == SYS_execve ||
            sysnum == SYS_execveat ||
            sysnum == SYS_getgroups ||
            sysnum == SYS_setgroups ||
            sysnum == SYS_prctl ||
            sysnum == SYS_capset ||
            sysnum == SYS_capget ||
            sysnum == SYS_acct ||
            sysnum == SYS_add_key ||
            sysnum == SYS_bpf ||
            sysnum == SYS_clock_adjtime ||
            sysnum == SYS_clock_settime ||
            sysnum == SYS_delete_module ||
            sysnum == SYS_finit_module ||
            sysnum == SYS_get_mempolicy ||
            sysnum == SYS_init_module ||
            sysnum == SYS_kcmp ||
            sysnum == SYS_kexec_load ||
            sysnum == SYS_keyctl ||
            sysnum == SYS_lookup_dcookie ||
            sysnum == SYS_mbind ||
            sysnum == SYS_mount ||
            sysnum == SYS_move_pages ||
            sysnum == SYS_name_to_handle_at ||
            sysnum == SYS_nfsservctl ||
            sysnum == SYS_open_by_handle_at ||
            sysnum == SYS_perf_event_open ||
            sysnum == SYS_personality ||
            sysnum == SYS_pivot_root ||
            sysnum == SYS_process_vm_readv ||
            sysnum == SYS_process_vm_writev ||
            sysnum == SYS_ptrace ||
            sysnum == SYS_quotactl ||
            sysnum == SYS_reboot ||
            sysnum == SYS_request_key ||
            sysnum == SYS_set_mempolicy ||
            sysnum == SYS_setns ||
            sysnum == SYS_settimeofday ||
            sysnum == SYS_socket ||
            sysnum == SYS_socketpair ||
            sysnum == SYS_utimes ||
            sysnum == SYS_swapon ||
            sysnum == SYS_swapoff || 
            sysnum == SYS_sysfs ||
            sysnum == SYS__sysctl ||
            sysnum == SYS_umount2 ||
            sysnum == SYS_unshare ||
            sysnum == SYS_uselib ||
            sysnum == SYS_userfaultfd ||
            sysnum == SYS_ustat);
}

static bool
syscall_filter(void *drcontext, int sysnum)
{
    sysnum = sysnum % 0x900000;
    return syscall_check(sysnum);
}

/*
 * This function filters syscalls (as seen from the list above) and
 * also registers signal handlers for hooking.
 */

static bool
event_pre_syscall(void *drcontext, int sysnum)
{
    int sig;
    struct sigaction *act;

    sysnum = sysnum % 0x900000;
    if (syscall_check(sysnum))
    {
        DERR("Bad cat!\n");
        dr_syscall_set_result(drcontext, -1);
        dr_abort();
        return false;
    }

    if (sysnum == SYS_sigaction || sysnum == SYS_rt_sigaction)
    {
        sig = dr_syscall_get_param(drcontext, 0);
        act = (struct sigaction *)dr_syscall_get_param(drcontext, 1);
        if (!act)
        {
            DPRINT("Handler being deregistered.\n");
            return true;
        }

        if (sig >= MAX_SIGHANDLERS)
        {
            DERR("Invalid signal.\n");
            dr_abort();
        }

        if (act->sa_flags & SA_SIGINFO)
        {
            DPRINT("SA_SIGACTION: %p\n", act->sa_sigaction);
            dr_mutex_lock(handlers_lock);
            handlers[sig] = (app_pc)((uint)act->sa_sigaction & ~1);
            dr_mutex_unlock(handlers_lock);
        }
        else if (act->sa_handler != SIG_DFL || act->sa_handler != SIG_IGN)
        {
            DPRINT("SA_HANDLER: %p\n", act->sa_handler);
            dr_mutex_lock(handlers_lock);
            handlers[sig] = (app_pc)((uint)act->sa_handler & ~1);
            dr_mutex_unlock(handlers_lock);
        }

        /* We don't care about default handlers */
    }
    return true;
}

/***** SIGNATURES *****/

/*
 * For identifying CRT code.
 */
static bool
match_crt_signature(instrlist_t *bb)
{
    instr_t *instrp;
    byte *raw;

    instrp = instrlist_first_app(bb);
    raw = instr_get_raw_bits(instrp);

    if (*(uint *)raw == 0xe3a0b000)
    {
        instrp = instr_get_next(instrp);
        if (!instrp) return false;
        raw = instr_get_raw_bits(instrp);
        return *(uint *)raw == 0xe3a0e000;
    }

    if (*(uint *)raw == 0x0b00f04f)
    {
        instrp = instr_get_next(instrp);
        if (!instrp) return false;
        raw = instr_get_raw_bits(instrp);
        return *(uint *)raw == 0x0e00f04f;
    }

    return false;
}

/*
 * For identifying setjmp.
 */
static bool
match_setjmp_signature(instrlist_t *bb)
{
    instr_t *instrp;
    byte *raw;

    instrp = instrlist_first_app(bb);
    raw = instr_get_raw_bits(instrp);

    if (*(uint *)(raw - 4) == 0xf102ecec)
    {
        return *(uint *)(raw - 8) == 0xe102ecec;
    }

    if (*(uint *)(raw - 4) == 0xececf102)
    {
        return *(uint *)(raw - 8) == 0xecece102;
    }

    if (*(uint *)raw == 0xa102ecec)
    {
        return *(uint *)(raw + 4) == 0xb102ecec;
    }

    if (*(uint *)raw == 0xececa102)
    {
        return *(uint *)(raw + 4) == 0xececb102;
    }

    return false;
}

/*
 * For identifying longjmp.
 */
static bool
match_longjmp_signature(instrlist_t *bb)
{
    instr_t *instrp;
    byte *raw;

    instrp = instrlist_first_app(bb);
    raw = instr_get_raw_bits(instrp);

    if (*(uint *)(raw - 4) == 0xf102ecfc)
    {
        return *(uint *)(raw - 8) == 0xe102ecfc;
    }

    if (*(uint *)(raw - 4) == 0xecfcf102)
    {
        return *(uint *)(raw - 8) == 0xecfce102;
    }

    if (*(uint *)raw == 0xa102ecfc)
    {
        return *(uint *)(raw + 4) == 0xb102ecfc;
    }

    if (*(uint *)raw == 0xecfca102)
    {
        return *(uint *)(raw + 4) == 0xecfcb102;
    }

    return false;
}

/*
 * For identifying __restore_core_regs.
 */
static bool
match_restore_core_regs_signature(instrlist_t *bb)
{
    int i;
    instr_t *instrp;
    byte *raw;

    instrp = instrlist_last_app(bb);
    
    if (instr_is_return(instrp))
    {
        for (i = 5; instrp && i;
             instrp = instr_get_prev_app(instrp), i--)
        {
            raw = instr_get_raw_bits(instrp);
            if (*(uint *)raw == 0xe8900fff ||
                *(uint *)raw == 0x0fffe890)
            {
                return true;
            }
        }
    }

    return false;
}

/***** OTHER INSTRUMENTATION *****/

/*
 * Basic block entry hook.
 */
static void
bb_instrument_entry(uint next_l, uint next_h, uint sp)
{
    int i;
    uint res;
    void *drcontext;
    struct thread_info *tls;

    drcontext = dr_get_current_drcontext();
    tls = (struct thread_info *)dr_get_tls_field(drcontext);

    if (!found_main) return;

    if (tls->shadow_count >= MAX_SHADOW_SIZE)
    {
        DERR("Call stack depth exceeded.\n");
        dr_abort();
    }

    res = (next_h << 16) + next_l;
    tls->shadow_stack[tls->shadow_count].lr = res;
    tls->shadow_stack[tls->shadow_count].sp = sp;
    tls->shadow_stack[tls->shadow_count].persist = 0;
    tls->shadow_count++;
}

static void
insert_entry_instr(void *drcontext, void *tag, instrlist_t *bb,
                   uint next)
{
    dr_insert_clean_call(drcontext, bb, instrlist_last(bb),
                         bb_instrument_entry, false, 3,
                         OUI((uint)next & 0xffff, OPSZ_2),
                         OUI((uint)next >> 16, OPSZ_2),
                         OCR(DR_REG_SP));
}

/*
 * Finding IT blocks.
 */
static instr_t *
get_it_instr(instr_t *target)
{
    int i = 4, j;
    instr_t *instrp;

    if (!instr_get_predicate(target)) return NULL;

    for (instrp = instr_get_prev(target); i && instrp;
         i--, instrp = instr_get_prev(instrp))
    {
        if (instr_get_opcode(instrp) == OP_it) return instrp;
    }

    return NULL;
}

/*
 * Basic block exit hook.
 */
static void
bb_instrument_exit(bool is_stack, uint sp, uint lr, int offset,
                   dr_pred_type_t exit_pred)
{
    int i;
    uint ret_addr;
    uint stack_addr;
    ushort persist;
    void *drcontext;
    dr_mcontext_t mc = { sizeof(mc), DR_MC_CONTROL };
    uint cpsr;
    bool Z, C, N, V, cond;
    struct thread_info *tls;
    struct frame *stack;

    drcontext = dr_get_current_drcontext();
    tls = (struct thread_info *)dr_get_tls_field(drcontext);

    if (!found_main) return;

    /* Check for predicated returns */
    if (exit_pred)
    {
        dr_get_mcontext(drcontext, &mc);
        cpsr = mc.cpsr;
        DPRINT("Predicate: %d\n", exit_pred);
        DPRINT("CPSR: %x\n", cpsr);
        N = ((cpsr & 0x80000000) != 0);
        Z = ((cpsr & 0x40000000) != 0);
        C = ((cpsr & 0x20000000) != 0);
        V = ((cpsr & 0x10000000) != 0);
        switch (exit_pred)
        {
            case DR_PRED_EQ:
                cond = Z;
                break;
            case DR_PRED_NE:
                cond = !Z;
                break;
            case DR_PRED_CS:
                cond = C;
                break;
            case DR_PRED_CC:
                cond = !C;
                break;
            case DR_PRED_MI:
                cond = N;
                break;
            case DR_PRED_PL:
                cond = !N;
                break;
            case DR_PRED_VS:
                cond = V;
                break;
            case DR_PRED_VC:
                cond = !V;
                break;
            case DR_PRED_HI:
                cond = (C && !Z);
                break;
            case DR_PRED_LS:
                cond = (!C || Z);
                break;
            case DR_PRED_GE:
                cond = (N == V);
                break;
            case DR_PRED_LT:
                cond = (N != V);
                break;
            case DR_PRED_GT:
                cond = (!Z && (N == V));
                break;
            case DR_PRED_LE:
                cond = (Z || (N != V));
                break;
            case DR_PRED_AL:
            default:
                cond = 1;
                break;
        }

        if (!cond)
        {
            DPRINT("Condition not satisfied.\n");
            return;
        }
    }

    ret_addr = is_stack ? (*(uint *)(sp + offset)): lr;

    ret_addr = ret_addr & ~1;

    stack_addr = is_stack ? sp + offset + 4 : sp;

    DPRINT("IS_STACK: %d\n", is_stack);
    DPRINT("RET: 0x%x\n", ret_addr);
    DPRINT("STACK: 0x%x\n", stack_addr);

    stack = tls->shadow_stack;

    while (tls->shadow_count)
    {
        tls->shadow_count--;
        if (stack[tls->shadow_count].lr == ret_addr &&
            stack[tls->shadow_count].sp == stack_addr)
        {
            persist = stack[tls->shadow_count].persist;
            if (persist == 1)
            {
                DPRINT("Persist.\n");
                stack[tls->shadow_count].persist++;
                tls->shadow_count++;
            }
            else if (persist > 1)
            {
                DERR("Bad catto!\n");
                dr_abort();
            }
            return;
        }
        DPRINT("Mismatch!\n");
    }

    DERR("No more food...\n");
    dr_abort();
}

static void
insert_exit_instr(void *drcontext, void *tag, instrlist_t *bb)
{
    /* Assume normal stack functionality */
    instr_t *instrp, *exit;
    opnd_t exit_opnd;
    reg_id_t ret_src;
    dr_pred_type_t exit_pred;

    exit = instrlist_last_app(bb);

    /* Find safe insertion point */
    instrp = get_it_instr(exit);
    instrp = instrp ? instrp : exit;

    /* Extract operand, LR/SP */
    exit_opnd = instr_get_src(exit, instr_num_srcs(exit) - 1);
    
    /* should be LR/SP */
    if (!opnd_is_reg(exit_opnd))
    {
        DERR("Unknown exit operand\n");
        dr_abort();
    }

    ret_src = opnd_get_reg(exit_opnd);
    if (ret_src != DR_REG_LR && ret_src != DR_REG_SP)
    {
        DERR("Unknown exit reg\n");
        dr_abort();
    }

    /* Extract predicate */
    exit_pred = instr_get_predicate(exit);

    DPRINT("FOUND PRED: %d\n", exit_pred);

    if (ret_src == DR_REG_LR)
    {
        /* No canary */
        dr_insert_clean_call(drcontext, bb, instrp,
                             bb_instrument_exit, false, 5,
                             OUI(0, OPSZ_1),
                             OCR(DR_REG_SP),
                             OCR(DR_REG_LR),
                             OUI(0, OPSZ_1),
                             OUI(exit_pred, OPSZ_1));
    }
    else
    {
        /*
         * -1 for SP, -1 for 0-indexing for -2 total.
         * Displacement always fits in 1 byte.
         * Possibly has canary.
         */
        dr_insert_clean_call(drcontext, bb, instrp,
                             bb_instrument_exit, false, 5,
                             OUI(1, OPSZ_1),
                             OCR(DR_REG_SP),
                             OCR(DR_REG_LR),
                             OUI((instr_num_dsts(exit) - 2) * 4,
                                                    OPSZ_1),
                             OUI(exit_pred, OPSZ_1));
    }
}

/*
 * Setjmp handling.
 */
static void
setjmp_persist()
{
    void *drcontext;
    struct thread_info *tls;

    drcontext = dr_get_current_drcontext();
    tls = (struct thread_info *)dr_get_tls_field(drcontext);

    if (!found_main) return;

    tls->shadow_stack[tls->shadow_count - 1].persist = 1;
}

static void
insert_setjmp_instr(void *drcontext, void *tag, instrlist_t *bb)
{
    dr_insert_clean_call(drcontext, bb, instrlist_last_app(bb),
                         setjmp_persist, false, 0);
}

/*
 * Exception/longjmp handling.
 */
static void
exception_return(bool is_restore_core_regs, uint sp, uint lr)
{
    void *drcontext;
    struct thread_info *tls;
    struct frame *stack;

    drcontext = dr_get_current_drcontext();
    tls = (struct thread_info *)dr_get_tls_field(drcontext);

    if (!found_main) return;

    /* Offset from pop pc */
    if (is_restore_core_regs) sp = sp + 4;

    stack = tls->shadow_stack;

    while (tls->shadow_count)
    {
        tls->shadow_count--;
        if (stack[tls->shadow_count].sp == sp)
        {
            if (stack[tls->shadow_count].persist)
            {
                DPRINT("Exception persist.\n");
                tls->shadow_count++;
            }
            return;
        }
        DPRINT("Mismatch!\n");
    }

    DERR("No more food...\n");
    dr_abort();
}

static void
insert_longjmp_instr(void *drcontext, void *tag, instrlist_t *bb)
{
    dr_insert_clean_call(drcontext, bb, instrlist_last_app(bb),
                         exception_return, false, 3,
                         OUI(0, OPSZ_1),
                         OCR(DR_REG_SP),
                         OCR(DR_REG_LR));
}

static void
insert_core_regs_instr(void *drcontext, void *tag, instrlist_t *bb)
{
    dr_insert_clean_call(drcontext, bb, instrlist_last_app(bb),
                         exception_return, false, 2,
                         OUI(1, OPSZ_1),
                         OCR(DR_REG_SP),
                         OCR(DR_REG_LR));
}

/*
 * CRT handling.
 */
static void
crt_grab_main(uint app_main)
{
    DPRINT("Found main at %x.\n", (app_pc)(app_main & ~1));
    main_entry = (app_pc)(app_main & ~1);
}

static void
insert_crt_instr(void *drcontext, void *tag, instrlist_t *bb)
{
    dr_insert_clean_call(drcontext, bb, instrlist_last_app(bb),
                         crt_grab_main, false, 1,
                         OCR(DR_REG_R0));
}

/*
 * Special main handling.
 */
static void
shadow_main_sp_lr(uint sp, uint app_main_lr)
{
    void *drcontext;
    struct thread_info *tls;

    if (run_main) return;
    drcontext = dr_get_current_drcontext();
    tls = (struct thread_info *)dr_get_tls_field(drcontext);
    tls->shadow_stack[tls->shadow_count].lr = app_main_lr & ~1;
    tls->shadow_stack[tls->shadow_count].sp = sp;
    tls->shadow_count++;
    run_main = true;
}

static void
insert_main_instr(void *drcontext, void *tag, instrlist_t *bb)
{
    dr_insert_clean_call(drcontext, bb, instrlist_first_app(bb),
                         shadow_main_sp_lr, false, 2,
                         OCR(DR_REG_SP),
                         OCR(DR_REG_LR));
}

/*
 * Signal handler hooking.
 */
static void
shadow_sighandler_sp_lr(uint sp, uint lr)
{
    void *drcontext;
    struct thread_info *tls;
    uint count;
    struct frame *stack;

    if (!found_main) return;
    drcontext = dr_get_current_drcontext();
    tls = (struct thread_info *)dr_get_tls_field(drcontext);
    count = tls->shadow_count;
    stack = tls->shadow_stack;

    stack[count].lr = lr & ~1;
    stack[count].sp = sp;
    tls->shadow_count++;
}

static void
insert_entry_sighandler_instr(void *drcontext, void *tag, instrlist_t *bb)
{
    dr_insert_clean_call(drcontext, bb, instrlist_first_app(bb),
                         shadow_sighandler_sp_lr, false, 2,
                         OCR(DR_REG_SP),
                         OCR(DR_REG_LR));
}

/*
 * Main function which determines what kinds of hooks to apply.
 */
static dr_emit_flags_t
event_bb(void *drcontext, void *tag, instrlist_t *bb,
         bool for_trace, bool translating)
{
    int opcode;
    instr_t *instrp = NULL;
    opnd_t opnd, opnd1, opnd2;
    app_pc bb_start;
    uint pc, i, n;

    if (for_trace || translating)
    {
        DPRINT("Skipping\n");
        return DR_EMIT_DEFAULT;
    }

    if (match_setjmp_signature(bb))
    {
        DPRINT("Found setjmp.\n");
        insert_setjmp_instr(drcontext, tag, bb);
        return DR_EMIT_DEFAULT;
    }

    if (match_longjmp_signature(bb))
    {
        DPRINT("Found longjmp.\n");
        insert_longjmp_instr(drcontext, tag, bb);
        return DR_EMIT_DEFAULT;
    }

    if (!found_restore_core_regs &&
        match_restore_core_regs_signature(bb))
    {
        DPRINT("Found restore_core_regs.\n");
        found_restore_core_regs = true;
        insert_core_regs_instr(drcontext, tag, bb);
        return DR_EMIT_DEFAULT;
    }

    instrp = instrlist_last_app(bb);
    pc = (uint)instr_get_app_pc(instrp);

    if (instr_is_call(instrp))
    {
        DPRINT("Instrument call\n");
        insert_entry_instr(drcontext, tag, bb, pc + instr_length(drcontext, instrp));
    }
    else if (instr_is_return(instrp))
    {
        /*
         * ldr pc, [lr, xx] is usually not a return and is used in PLT,
         * but passes instr_is_return.
         * However, ldr pc, [sp], #4 is a common return when only LR is pushed.
         */
        DPRINT("(Maybe) Instrument ret\n");
        opcode = instr_get_opcode(instrp);
        if (opcode != OP_ldr)
        {
            insert_exit_instr(drcontext, tag, bb);
        }
        else
        {
            if (instr_num_srcs(instrp) == 3)
            {
                opnd = instr_get_src(instrp, 0);
                opnd2 = instr_get_src(instrp, 2);
                if (opnd_is_base_disp(opnd) &&
                    opnd_is_reg(opnd2) &&
                    opnd_get_reg(opnd2) == DR_REG_SP)
                {
                    insert_exit_instr(drcontext, tag, bb);
                }
            }
        }
    }

    /* Attempt to find main */
    if (!main_entry)
    {
        /* Attempt instrumentation */
        instrp = instrlist_last_app(bb);
        if (match_crt_signature(bb) && instr_is_call(instrp))
        {
            DPRINT("Found CRT.\n");
            insert_crt_instr(drcontext, tag, bb);
        }
    }
    else if (!found_main)
    {
        /* Wait until main */
        if (instr_get_app_pc(instrlist_first_app(bb)) == main_entry)
        {
            DPRINT("Reached main.\n");
            found_main = true;
            insert_main_instr(drcontext, tag, bb);
        }
    }

    /* Instrument signal handlers */
    bb_start = instr_get_app_pc(instrlist_first_app(bb));
    for (i = 0; i < MAX_SIGHANDLERS; i++)
    {
        if (bb_start == handlers[i])
        {
            insert_entry_sighandler_instr(drcontext, tag, bb);
            break;
        }
    }

    return DR_EMIT_DEFAULT;
}

/*
 * Thread initialization handler.
 */
static void
event_thread_init(void *drcontext)
{
    file_t f;
    struct thread_info *tls;

    DPRINT("Starting thread.\n");
    tls = (struct thread_info *)dr_thread_alloc(drcontext, sizeof(struct thread_info));
    dr_set_tls_field(drcontext, tls);
    tls->shadow_count = 0;
}

/*
 * Thread exit handler.
 */
static void
event_thread_exit(void *drcontext)
{
    struct thread_info *tls;

    DPRINT("Ending thread.\n");
    tls = (struct thread_info *)dr_get_tls_field(drcontext);
    dr_thread_free(drcontext, tls, sizeof(struct thread_info));
}

/*
 * Exit handler.
 */
static void
event_exit(void)
{
    DERR("I am a cat\n");
    dr_abort();
}

/***** MAIN *****/

/*
 * Main function which registers all the handlers.
 */
DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    disassemble_set_syntax(DR_DISASM_ARM);
    dr_register_filter_syscall_event(syscall_filter);
    dr_register_pre_syscall_event(event_pre_syscall);
    dr_register_bb_event(event_bb);
    dr_register_thread_init_event(event_thread_init);
    dr_register_thread_exit_event(event_thread_exit);
    dr_register_exit_event(event_exit);

    handlers_lock = dr_mutex_create();
}
