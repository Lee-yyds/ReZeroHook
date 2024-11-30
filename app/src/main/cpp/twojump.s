.text
.align 2
.global _twojump_start
.global _twojump_end

_twojump_start:
    // 预留16字节存储地址
    .quad 0   // hookinfo 指针
    .quad 0   // hook函数指针

get_data:
    // 获取当前指令地址并计算偏移
    adr x16, get_data
    sub x16, x16, #16
    ldr x16, [x16]         // 加载hookinfo指针

    // 保存寄存器到HookInfo->ctx
    stp x0, x1, [x16, #0]
    stp x2, x3, [x16, #16]
    stp x4, x5, [x16, #32]
    stp x6, x7, [x16, #48]
    stp x8, x9, [x16, #64]
    stp x10, x11, [x16, #80]
    stp x12, x13, [x16, #96]
    stp x14, x15, [x16, #112]

    // 暂存x16,x17
    str x17, [sp, #-16]!
    mov x17, x16
    stp x16, x17, [x17, #128]
    ldr x17, [sp], #16
    stp x18, x19, [x17, #144]
    stp x20, x21, [x17, #160]
    stp x22, x23, [x17, #176]
    stp x24, x25, [x17, #192]
    stp x26, x27, [x17, #208]
    stp x28, x29, [x17, #224]
    str x30, [x17, #240]
    mov x16, sp
    str x16, [x17, #248]

    // 加载hook函数地址,并传递hookinfo指针
    adr x16, get_data
    sub x16, x16, #16
    mov x0, x16        // hookinfo指针作为第一个参数
    ldr x16, [x16, #8] // 加载hook函数指针
    blr x16

_twojump_end: