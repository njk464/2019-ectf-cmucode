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

/* Code Manipulation API Sample:
 * empty.c
 *
 * Serves as an example of an empty client that does nothing but
 * register for the exit event.
 */

#include "dr_api.h"
#include <stddef.h>
#include <sys/syscall.h>

#define COND_EQ 0
#define COND_NE 1
#define COND_CS 2
#define COND_CC 3
#define COND_MI 4
#define COND_PL 5
#define COND_VS 6
#define COND_VC 7
#define COND_HI 8
#define COND_LS 9
#define COND_GE 10
#define COND_LT 11
#define COND_GT 12
#define COND_LE 13
#define COND_AL 14

//#define DEBUG

#undef report_dynamorio_problem
#undef report_app_problem

#ifdef DEBUG
#define DPRINT(format,...) (dr_printf(format, ##__VA_ARGS__))
#else
#define DPRINT(format,...)
#endif

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
            sysnum == SYS_clone ||
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

static bool
has_call(instrlist_t *bb)
{
    /*
     * Checks if the last instruction is a BL, BLX or BLX_IND.
     * WARN: Calls should be the last instruction in a BB!
     */

    return instr_is_call(instrlist_last_app(bb));
}

static bool
has_ret(instrlist_t *bb)
{
    /*
     * Check for returns.
     * WARN: Rets should be the last instruction in a BB!
     */
    
    return instr_is_return(instrlist_last_app(bb));
}

/* TODO: Too heavyweight, factor out all these calls */
static void
bb_instrument_call()
{
    //instr_t instr;
    //void *drcontext;
    //dr_mcontext_t mcontext;

    //drcontext = dr_get_current_drcontext();
    //dr_get_mcontext(drcontext, &mcontext);
    //instr_init(drcontext, &instr);
    //disassemble(drcontext, mcontext.pc, STDOUT);
    //printf("Target: %p\n", instr_get_branch_target_pc(
}

static void
bb_instrument_call_cond()
{
}

static void
bb_instrument_ret(uint is_stack, uint addr, uint offset)
{
    uint real_addr;
    uint thumb;
    //instr_t instr2, instr4;
    void *drcontext;

    /* Calculate actual address */
    if (!is_stack)
    {
        real_addr = addr;
    }
    else
    {
        real_addr = *(uint *)(addr + offset);
    }

    thumb = real_addr & 1;
    real_addr = real_addr & ~1;
    DPRINT("Found ret addr: %p\n", real_addr);

    /*
     * Check valid - Don't know how to force disassembly mode so
     * doing this manually
     */
    drcontext = dr_get_current_drcontext();
    //instr_init(drcontext, &instr2);
    //instr_init(drcontext, &instr4);
    //decode(drcontext, (byte *)(real_addr - 2), &instr2);
    //decode(drcontext, (byte *)(real_addr - 4), &instr4);
    if (thumb)
    {
        DPRINT("Thumb:\n");
        DPRINT("-4: %hx\n-2: %hx\n", *(ushort *)(real_addr - 4), *(ushort *)(real_addr - 2));
#ifdef DEBUG
        disassemble(drcontext, real_addr - 2, STDOUT);
        disassemble(drcontext, real_addr - 4, STDOUT);
#endif
        if ((*(byte *)(real_addr - 3) & 0xf8) != 0xf0 &&              /* BL/BLX imm */
            (*(ushort *)(real_addr - 2) & 0xff87) != 0x4780)          /* BLX reg */
        {
            DPRINT("Very bad cat!\n");
            dr_abort();
        }
    }
    else
    {
        DPRINT("Arm:\n");
        DPRINT("-4: %x\n", *(uint *)(real_addr - 4));
#ifdef DEBUG
        disassemble(drcontext, real_addr - 2, STDOUT);
        disassemble(drcontext, real_addr - 4, STDOUT);
#endif
        if ((*(byte *)(real_addr - 1) & 0x0f) != 0x0b &&              /* BL imm */
            (*(byte *)(real_addr - 1) & 0xfe) != 0xfa &&              /* BLX imm */
            (*(uint *)(real_addr - 4) & 0x0ffffff0) != 0x012fff30)    /* BLX reg */
        {
            DPRINT("Very bad cat!\n");
            dr_abort();
        }
    }
}

static void
bb_instrument_ret_cond()
{
}

static instr_t *
get_it_instr(void *drcontext, instr_t *target)
{
    /*
     * Find itxxx instruction containing the call/ret.
     * itxxx instructions cannot nest.
     * itxxx instructions can only have branches at the end of their block.
     * At most one branch per block.
     * WARN: Might need to use instruction init/reset/decode/free
     */

    int i = 4, j;
    instr_t *instrp;

    /* Unpredicated instrs are safe to instrument */
    if (!instr_get_predicate(target)) return NULL;

    /* Instruction is in some IT block */
    for (instrp = instr_get_prev(target); i && instrp;
         i--, instrp = instr_get_prev(instrp))
    {
        if (instr_get_opcode(instrp) == OP_it)
        {
            DPRINT("IT count: %d\n", instr_it_block_get_count(instrp));
            for (j = 0; j < instr_it_block_get_count(instrp); j++)
            {
                DPRINT("IT pred %d: %d\n", j, instr_it_block_get_pred(instrp, j));
            }
            return instrp;
        }
    }

    return NULL;
}

static void
insert_call_instr(void *drcontext, void *tag, instrlist_t *bb)
{
    instr_t *instrp, *call;
    opnd_t call_opnd;

    call = instrlist_last_app(bb);
    instrp = get_it_instr(drcontext, call);
    if (!instrp)
    {
        dr_insert_clean_call(drcontext, bb, call,
                             bb_instrument_call, false, 0);
    }
    else
    {
        dr_insert_clean_call(drcontext, bb, instrp,
                             bb_instrument_call_cond, false, 0);
    }

    if (instr_is_call_direct(call))
    {
        DPRINT("Call target: %p\n", instr_get_branch_target_pc(call));
    }
    else
    {
        call_opnd = instr_get_src(call, instr_num_srcs(call) - 1);
        DPRINT("Call target operand: ");
#ifdef DEBUG
        opnd_disassemble(drcontext, call_opnd, STDOUT);
#endif
        DPRINT("\n");
    }
}

static void
insert_ret_instr(void *drcontext, void *tag, instrlist_t *bb)
{
    instr_t *instrp, *ret;
    opnd_t ret_opnd, op2;

    ret = instrlist_last_app(bb);

    /* Find IT block if applicable */
    instrp = get_it_instr(drcontext, ret);

    /* Returns are always indirect */
    ret_opnd = instr_get_src(ret, instr_num_srcs(ret) - 1);
    DPRINT("Return target operand: ");
#ifdef DEBUG
    opnd_disassemble(drcontext, ret_opnd, STDOUT);
#endif
    
    /* Extract offset if sp. src should be LR or SP generally. */
    if (opnd_get_reg(ret_opnd) == DR_REG_SP)
    {
        /*
         * -1 for sp and -1 for 0 indexing
         * Assumes LDM(IA), i.e. normal push/pop behavior
         */
        DPRINT(" + 0x%x", (instr_num_dsts(ret) - 2) * 4);
    }
    DPRINT("\n");

    if (!instrp)
    {
        if (opnd_get_reg(ret_opnd) == DR_REG_LR)
        {
            dr_insert_clean_call(drcontext, bb, ret,
                                 bb_instrument_ret, false, 3,
                                 opnd_create_immed_uint(0, OPSZ_4),
                                 ret_opnd,
                                 opnd_create_immed_uint(0, OPSZ_4));
        }
        else
        {
            /*op2 = opnd_create_base_disp(DR_REG_SP, DR_REG_NULL, 0,
                                        (instr_num_dsts(ret) - 2) * 4, 4);*/
            dr_insert_clean_call(drcontext, bb, ret,
                                 bb_instrument_ret, false, 3,
                                 opnd_create_immed_uint(1, OPSZ_4),
                                 ret_opnd,
                                 opnd_create_immed_uint((instr_num_dsts(ret) - 2) * 4, OPSZ_4));
        }
    }
    else
    {
        /* Not now */
        //dr_insert_clean_call(drcontext, bb, instrp,
        //                     bb_instrument_ret, false, 0);
    }

}

static dr_emit_flags_t
event_bb(void *drcontext, void *tag, instrlist_t *bb,
         bool for_trace, bool translating)
{
    if (for_trace || translating)
    {
        return DR_EMIT_DEFAULT;
    }

    DPRINT("======================\n");

    if (has_call(bb))
    {
        /* Not now */
        //insert_call_instr(drcontext, tag, bb);
    }
    else if (has_ret(bb))
    {
        insert_ret_instr(drcontext, tag, bb);
    }

#ifdef DEBUG
    instrlist_disassemble(drcontext, tag, bb, STDOUT);
#endif

    return DR_EMIT_DEFAULT;
}

static void
event_fail(void *drcontext, void *tag, dr_mcontext_t *mcontext,
           bool restore_memory, bool app_code_consistent)
{
    DPRINT("Very very bad cat!\n");
    dr_abort();
}

static void
event_exit(void)
{
    DPRINT("I am a cat\n");
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    disassemble_set_syntax(DR_DISASM_ARM);
    dr_register_filter_syscall_event(syscall_filter);
    dr_register_pre_syscall_event(event_pre_syscall);
    dr_register_bb_event(event_bb);
    dr_register_restore_state_event(event_fail);
    dr_register_exit_event(event_exit);
}
