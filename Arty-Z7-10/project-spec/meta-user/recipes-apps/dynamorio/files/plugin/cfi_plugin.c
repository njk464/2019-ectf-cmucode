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
#include <stddef.h>
#include <sys/syscall.h>

/***** DEFINES *****/

//#define DEBUG

#undef report_dynamorio_problem
#undef report_app_problem

#ifdef DEBUG
#define DPRINT(format,...)  (dr_fprintf(STDOUT, format, ##__VA_ARGS__))
#define DERR(format,...)    (dr_fprintf(STDOUT, format, ##__VA_ARGS__))
#else
#define DERR(format,...)  
#define DPRINT(format,...)
#endif


#define IMP(bb, w, i)       (instrlist_meta_preinsert((bb), (w), (i)))
#define OCR(r)              (opnd_create_reg((r)))
#define OUI(i, sz)          (opnd_create_immed_uint((i), (sz)))
#define OBD(b, i, s, d, sz) (opnd_create_base_disp((b), (i), (s), (d), (sz)))

#define MAX_SHADOW_SIZE 800

/***** STATIC GLOBALS AND STRUCTS *****/

static bool found_main = false;
static bool run_main = false;
static app_pc main_entry = NULL;

struct thread_info
{
    int regset;
    int shadow_count;
    app_pc shadow_stack[MAX_SHADOW_SIZE];
};

/***** REGSET MANIP *****/

void regset_clear(struct thread_info *tls)
{
    tls->regset = 1 << dr_get_stolen_reg();
}

void regset_freeze(struct thread_info *tls, reg_id_t id)
{
    tls->regset |= (1 << id);
}

reg_id_t regset_get(struct thread_info *tls)
{
    reg_id_t id;

    for (id = DR_REG_R0; id <= DR_REG_R10; id++)
    {
        if (tls->regset & (1 << id)) continue;
        tls->regset |= (1 << id);
        return id;
    }

    DERR("Insufficient registers.\n");
    dr_abort();
    return DR_REG_INVALID;
}

void regset_put(struct thread_info *tls, reg_id_t id)
{
    if (id == dr_get_stolen_reg())
    {
        DERR("Cannot put stolen reg.\n");
        dr_abort();
        return;
    }

    if (tls->regset & (1 << id))
    {
        tls->regset &= ~(1 << id);
        return;
    }

    DERR("Register %d already free.\n", id);
    dr_abort();
}

/***** SYSCALL FILTER *****/

static bool
syscall_check(int sysnum)
{
    return (sysnum == SYS_execve ||
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
    return syscall_check(sysnum);
}

static bool
event_pre_syscall(void *drcontext, int sysnum)
{
    if (syscall_check(sysnum))
    {
        DPRINT("Bad cat!\n");
        dr_syscall_set_result(drcontext, -1);
        dr_abort();
        return false;
    }
    return true;
}

/***** OTHER INSTRUMENTATION *****/

#ifdef DEBUG
static void
bb_instrument_entry(uint next_l, uint next_h)
{
    int i;
    app_pc res;
    void *drcontext;
    struct thread_info *tls;

    if (!found_main) return;

    drcontext = dr_get_current_drcontext();
    tls = (struct thread_info *)dr_get_tls_field(drcontext);

#ifdef DEBUG
    DPRINT("I'm calling!\n");

    DPRINT("STACK: ");
    for (i = 0; i < tls->shadow_count; i++)
    {
        DPRINT("%p ", tls->shadow_stack[i]);
    }
    DPRINT("\n");
#endif

    if (tls->shadow_count >= MAX_SHADOW_SIZE)
    {
        DERR("Call stack depth exceeded.\n");
        dr_abort();
    }

    res = (app_pc)((next_h << 16) + next_l);
    tls->shadow_stack[tls->shadow_count++] = res;

#ifdef DEBUG
    DPRINT("STACK AFT: ");
    for (i = 0; i < tls->shadow_count; i++)
    {
        DPRINT("%p ", tls->shadow_stack[i]);
    }
    DPRINT("\n");
#endif
}
#endif

static void
insert_entry_instr(void *drcontext, void *tag, instrlist_t *bb,
                   app_pc next)
{
    reg_id_t stolen;
    reg_id_t flags, tls_base, imm, count, next_reg, stack_addr;
    struct thread_info *tls;
    instr_t *where;
    instr_t *l_not_found_main, *l_no_abort;

    where = instrlist_last_app(bb);

    tls = (struct thread_info *)dr_get_tls_field(drcontext);
    regset_clear(tls);

    stolen = dr_get_stolen_reg();

    flags = regset_get(tls);
    dr_save_reg(drcontext, bb, where, flags, SPILL_SLOT_1);
    IMP(bb, where,
        INSTR_CREATE_mrs(drcontext, OCR(flags), OCR(DR_REG_CPSR)));

    imm = regset_get(tls);
    dr_save_reg(drcontext, bb, where, imm, SPILL_SLOT_2);
    instrlist_insert_mov_immed_ptrsz(drcontext, (uint)&found_main,
                                     OCR(imm), bb, where, NULL, NULL);
    IMP(bb, where,
        INSTR_CREATE_ldrb(drcontext, OCR(imm),
                          OBD(imm, DR_REG_NULL, 0, 0, OPSZ_1)));

    l_not_found_main = INSTR_CREATE_label(drcontext);
    IMP(bb, where,
        INSTR_CREATE_cmp(drcontext, OCR(imm), OUI(0, OPSZ_4)));
    IMP(bb, where,
        INSTR_PRED(INSTR_CREATE_b(drcontext, opnd_create_instr(l_not_found_main)),
                   DR_PRED_EQ));

    tls_base = regset_get(tls);
    dr_save_reg(drcontext, bb, where, tls_base, SPILL_SLOT_3);
    dr_insert_read_tls_field(drcontext, bb, where, tls_base);

    count = regset_get(tls);
    dr_save_reg(drcontext, bb, where, count, SPILL_SLOT_4);
    IMP(bb, where,
        INSTR_CREATE_ldr(drcontext, OCR(count),
                         OBD(tls_base, DR_REG_NULL, 0,
                             (uint)offsetof(struct thread_info, shadow_count),
                             OPSZ_4)));

    l_no_abort = INSTR_CREATE_label(drcontext);
    instrlist_insert_mov_immed_ptrsz(drcontext, MAX_SHADOW_SIZE - 1, OCR(imm),
                                     bb, where, NULL, NULL);
    IMP(bb, where,
        INSTR_CREATE_cmp(drcontext, OCR(count), OCR(imm)));
    IMP(bb, where,
        INSTR_PRED(INSTR_CREATE_b(drcontext, opnd_create_instr(l_no_abort)),
                   DR_PRED_LS));

    dr_insert_call(drcontext, bb, where, dr_abort, 0);

    IMP(bb, where, l_no_abort);
    instrlist_insert_mov_immed_ptrsz(drcontext, (uint)next, OCR(imm),
                                     bb, where, NULL, NULL);

    stack_addr = regset_get(tls);
    dr_save_reg(drcontext, bb, where, stack_addr, SPILL_SLOT_5);
    IMP(bb, where,
        INSTR_CREATE_add(drcontext, OCR(stack_addr), OCR(tls_base),
                         OUI((uint)offsetof(struct thread_info, shadow_stack), OPSZ_4)));

    IMP(bb, where,
        INSTR_CREATE_str(drcontext,
                         OBD(stack_addr, count, 4, 0, OPSZ_4),
                         OCR(imm)));
    IMP(bb, where,
        INSTR_CREATE_add(drcontext, OCR(count), OCR(count), OUI(1, OPSZ_4)));
    IMP(bb, where,
        INSTR_CREATE_str(drcontext,
                         OBD(tls_base, DR_REG_NULL, 0,
                             (uint)offsetof(struct thread_info, shadow_count),
                             OPSZ_4),
                         OCR(count)));

    dr_restore_reg(drcontext, bb, where, stack_addr, SPILL_SLOT_5);
    
    dr_restore_reg(drcontext, bb, where, count, SPILL_SLOT_4);

    dr_restore_reg(drcontext, bb, where, tls_base, SPILL_SLOT_3);

    IMP(bb, where, l_not_found_main);
    dr_restore_reg(drcontext, bb, where, imm, SPILL_SLOT_2);

    IMP(bb, where,
        INSTR_CREATE_msr(drcontext, OCR(DR_REG_CPSR),
                         OPND_CREATE_INT_MSR_NZCVQG(),
                         OCR(flags)));
    dr_restore_reg(drcontext, bb, where, flags, SPILL_SLOT_1);

    /*
    dr_insert_clean_call(drcontext, bb, instrlist_last(bb),
                         bb_instrument_entry, false, 2,
                         opnd_create_immed_uint((uint)next & 0xffff, OPSZ_2),
                         opnd_create_immed_uint((uint)next >> 16, OPSZ_2));
    */
}

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

static void
bb_instrument_exit(bool is_stack, app_pc addr, int offset,
                   dr_pred_type_t exit_pred)
{
    int i;
    app_pc ret_addr;
    void *drcontext;
    dr_mcontext_t mc = { sizeof(mc), DR_MC_CONTROL };
    uint cpsr;
    bool Z, C, N, V, cond;
    struct thread_info *tls;

    if (!found_main) return;

    drcontext = dr_get_current_drcontext();
    tls = (struct thread_info *)dr_get_tls_field(drcontext);

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

    ret_addr = is_stack ? *(app_pc *)(addr + offset) : addr;
    ret_addr = (app_pc)((uint)ret_addr & ~1);

#ifdef DEBUG
    DPRINT("STACK: ");
    for (i = 0; i < tls->shadow_count; i++)
    {
        DPRINT("%p ", tls->shadow_stack[i]);
    }
    DPRINT("\n");

    DPRINT("RET: %p\n", ret_addr);
#endif

    while (tls->shadow_count)
    {
        if (tls->shadow_stack[--tls->shadow_count] == ret_addr)
        {
#ifdef DEBUG
            DPRINT("STACK AFT: ");
            for (i = 0; i < tls->shadow_count; i++)
            {
                DPRINT("%p ", tls->shadow_stack[i]);
            }
            DPRINT("\n");
#endif
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
    dr_pred_type_t exit_pred;

    exit = instrlist_last_app(bb);

    /* Find safe insertion point */
    instrp = get_it_instr(exit);
    instrp = instrp ? instrp : exit;

    /* Extract operand, LR/SP */
    exit_opnd = instr_get_src(exit, instr_num_srcs(exit) - 1);

    /* Extract predicate */
    exit_pred = instr_get_predicate(exit);

    DPRINT("FOUND PRED: %d\n", exit_pred);

    /* FIXME: Check for stack cleanup in IT block */
    if (opnd_get_reg(exit_opnd) == DR_REG_LR)
    {
        dr_insert_clean_call(drcontext, bb, instrp,
                             bb_instrument_exit, false, 4,
                             opnd_create_immed_uint(0, OPSZ_1),
                             exit_opnd,
                             opnd_create_immed_int(0, OPSZ_1),
                             opnd_create_immed_int(exit_pred, OPSZ_1));
    }
    else
    {
        /*
         * -1 for SP, -1 for 0-indexing
         * Always fits in 1 byte
         */
        dr_insert_clean_call(drcontext, bb, instrp,
                             bb_instrument_exit, false, 4,
                             opnd_create_immed_uint(1, OPSZ_1),
                             exit_opnd,
                             opnd_create_immed_int((instr_num_dsts(exit) - 2) * 4,
                                                   OPSZ_1),
                             opnd_create_immed_int(exit_pred, OPSZ_1));
    }
}

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

static void
crt_grab_main(app_pc app_main)
{
    DPRINT("Found main at %p.\n", (app_pc)((uint)app_main & ~1));
    main_entry = (app_pc)((uint)app_main & ~1);
}

static void
insert_crt_instr(void *drcontext, void *tag, instrlist_t *bb)
{
    dr_insert_clean_call(drcontext, bb, instrlist_last_app(bb),
                         crt_grab_main, false, 1,
                         opnd_create_reg(DR_REG_R0));
}

static void
shadow_main_lr(app_pc app_main_lr)
{
    void *drcontext;
    struct thread_info *tls;

    if (run_main) return;
    drcontext = dr_get_current_drcontext();
    tls = (struct thread_info *)dr_get_tls_field(drcontext);
    tls->shadow_stack[tls->shadow_count++] = (app_pc)((uint)app_main_lr & ~1);
    run_main = true;
}

static void
insert_main_instr(void *drcontext, void *tag, instrlist_t *bb)
{
    dr_insert_clean_call(drcontext, bb, instrlist_first_app(bb),
                         shadow_main_lr, false, 1,
                         opnd_create_reg(DR_REG_LR));
}

static dr_emit_flags_t
event_bb(void *drcontext, void *tag, instrlist_t *bb,
         bool for_trace, bool translating)
{
    instr_t *instrp = NULL;
    opnd_t opnd, opnd1, opnd2;
    app_pc pc;

    DPRINT("=========================\n");

    if (for_trace || translating)
    {
        DPRINT("Skipping\n");
        return DR_EMIT_DEFAULT;
    }

    instrp = instrlist_last_app(bb);
    pc = instr_get_app_pc(instrp);

    if (instr_is_call(instrp))
    {
        /* FIXME: Not handling predicated */
        insert_entry_instr(drcontext, tag, bb, pc + instr_length(drcontext, instrp));
    }
    else if (instr_is_return(instrp))
    {
        /*
         * ldr pc, [lr, xx] is usually not a return and is used in PLT,
         * but passes instr_is_return.
         * However, ldr pc, [sp], #4 is a common return when only LR is pushed.
         */
        if (instr_get_opcode(instrp) != OP_ldr)
        {
            insert_exit_instr(drcontext, tag, bb);
        }
        else if (instr_num_srcs(instrp) == 3)
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

    /* Attempt to find main */
    if (!main_entry)
    {
        /* Attempt instrumentation */
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

#ifdef DEBUG
    instrlist_disassemble(drcontext, tag, bb, STDOUT);
#endif

    return DR_EMIT_DEFAULT;
}

static void
event_thread_init(void *drcontext)
{
    struct thread_info *tls;

    DPRINT("Starting thread.\n");
    tls = (struct thread_info *)dr_thread_alloc(drcontext, sizeof(struct thread_info));
    dr_set_tls_field(drcontext, tls);
    tls->shadow_count = 0;
}

static void
event_thread_exit(void *drcontext)
{
    struct thread_info *tls;

    DPRINT("Ending thread.\n");
    tls = (struct thread_info *)dr_get_tls_field(drcontext);
    dr_thread_free(drcontext, tls, sizeof(struct thread_info));
}

static void
event_exit(void)
{
    DERR("I am a cat\n");
}

/***** MAIN *****/

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
}
