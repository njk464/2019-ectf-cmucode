# 1 "/home/ubuntu/dynamorio_bin/HOTPATCH/dynamorio/ext/drwrap/drwrap_asm_arm.asm"
# 1 "/home/ubuntu/dynamorio_bin/HOTPATCH/build_arm/ext/drwrap//"
# 1 "<built-in>"
# 1 "<command-line>"
# 1 "/usr/arm-linux-gnueabihf/include/stdc-predef.h" 1 3
# 1 "<command-line>" 2
# 1 "/home/ubuntu/dynamorio_bin/HOTPATCH/dynamorio/ext/drwrap/drwrap_asm_arm.asm"
# 37 "/home/ubuntu/dynamorio_bin/HOTPATCH/dynamorio/ext/drwrap/drwrap_asm_arm.asm"
# 1 "/home/ubuntu/dynamorio_bin/HOTPATCH/build_arm/cmake/cpp2asm_defines.h" 1
# 38 "/home/ubuntu/dynamorio_bin/HOTPATCH/dynamorio/ext/drwrap/drwrap_asm_arm.asm" 2

.text





# 53 "/home/ubuntu/dynamorio_bin/HOTPATCH/dynamorio/ext/drwrap/drwrap_asm_arm.asm"
        .align 0 
.global replace_native_xfer 
.hidden replace_native_xfer 
.type replace_native_xfer, %function
replace_native_xfer:
        push {r0}

        blx replace_native_xfer_app_retaddr
        push {r0}


        blx replace_native_xfer_target
        mov r3, r0


        pop {lr}
        pop {r0}
        bx r3

        bx lr
       




.global replace_native_ret_imms 
.hidden replace_native_ret_imms
.global replace_native_ret_imms_end 
.hidden replace_native_ret_imms_end

        .align 0 
.global replace_native_rets 
.hidden replace_native_rets 
.type replace_native_rets, %function
replace_native_rets:
        bx lr
replace_native_ret_imms:
replace_native_ret_imms_end:
        nop
       





        .align 0 
.global get_cur_xsp 
.hidden get_cur_xsp 
.type get_cur_xsp, %function
get_cur_xsp:
        mov r0, sp
        bx lr
       



