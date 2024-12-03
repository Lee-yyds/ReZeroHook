.text
.align 2
.global _twojump_start
.global _twojump_end
//.hidden能取消位置无关代码报错
.hidden _twojump_start
_twojump_start:
    // 预留16字节存储地址
    .quad 0   // hookinfo 指针
    .quad 0   // hook函数指针
    // 保存lr
    stp x30, xzr, [sp, #-0x10]!
     // 保存原始x0-x1和sp
    stp x0, x1, [sp, #-0x10]!
    // 保存工作寄存器
    stp x16, x17, [sp, #-0x10]!
     // 获取当前PC值
    ldr x16, _twojump_start
    // 保存基地址到x19(因为后面还要用)
    // mov x19, x16
    // 加载hookinfo指针和hook函数指针
    ldp x16, x17, [x16]
    // 调整基址到 ctx 成员
    add x16, x16, #0x30
    // 保存寄存器到 HookInfo->ctx
    ldp x0, x1, [sp], #0x10    // 恢复x16,x17
    stp x0, x1, [x16, #128]  // 保存原始x16,x17 crash
    // 恢复x0,x1到临时寄存器
    ldp x0, x1, [sp], #0x10    // 从栈上加载原始x0,x1
    // 恢复栈指针和原始sp值
    ldp x30, xzr, [sp], #0x10  // 恢复lr
 //   ldp x2, x3, [sp], #16    // x3包含原始sp
 //   mov sp, x3               // 恢复原始sp值

    // 保存所有寄存器到ctx
    stp x0, x1, [x16, #0]
    stp x2, x3, [x16, #16]
    stp x4, x5, [x16, #32]
    stp x6, x7, [x16, #48]
    stp x8, x9, [x16, #64]
    stp x10, x11, [x16, #80]
    stp x12, x13, [x16, #96]
    stp x14, x15, [x16, #112]
    stp x18, x19, [x16, #144]
    stp x20, x21, [x16, #160]
    stp x22, x23, [x16, #176]
    stp x24, x25, [x16, #192]
    stp x26, x27, [x16, #208]
    stp x28, x29, [x16, #224]
    str x30, [x16, #240]
    str x3, [x16, #248]      // 保存原始sp值

    // 调用pre_callback
    sub x0, x16, #48         // HookInfo作为第一个参数
    ldr x17, [x0]            // 加载pre_callback函数指针
    blr x17                  // 调用pre_callback

    // 重新获取HookInfo指针(使用保存的基地址)
    //ldp x16, x17, [x19]      // 从基地址重新加载HookInfo指针
    //add x17, x16, #48        // x17指向ctx
    // 计算基地址
    ldr x16, _twojump_start
    add x16, x16, #0x30
    // 恢复所有寄存器 比如在hook里修改了，那这里就要还原了
    ldp x0, x1, [x16, #0]
    ldp x2, x3, [x17, #16]
    ldp x4, x5, [x16, #32]
    ldp x6, x7, [x16, #48]
    ldp x8, x9, [x16, #64]
    ldp x10, x11, [x16, #80]
    ldp x12, x13, [x16, #96]
    ldp x14, x15, [x16, #112]
    ldp x18, x19, [x16, #144]
    ldp x20, x21, [x16, #160]
    ldp x22, x23, [x16, #176]
    ldp x24, x25, [x16, #192]
    ldp x26, x27, [x16, #208]
    ldp x28, x29, [x16, #224]
    ldr x30, [x16, #240]
    sub x16, x16, #0x30
    // 调用原函数
    ldr x17, [x16, #16]      // 加载原函数地址
    blr x17

    sub x16, x0, #48         // 获取HookInfo
    add x17, x16, #48        // x17指向ctx

    // 再次保存寄存器到ctx
    stp x0, x1, [x17, #0]
    stp x2, x3, [x17, #16]
    stp x4, x5, [x17, #32]
    stp x6, x7, [x17, #48]
    stp x8, x9, [x17, #64]
    stp x10, x11, [x17, #80]
    stp x12, x13, [x17, #96]
    stp x14, x15, [x17, #112]
    stp x18, x19, [x17, #144]
    stp x20, x21, [x17, #160]
    stp x22, x23, [x17, #176]
    stp x24, x25, [x17, #192]
    stp x26, x27, [x17, #208]
    stp x28, x29, [x17, #224]

    // 调用post_callback
    mov x0, x16              // HookInfo作为第一个参数
    ldr x16, [x16, #24]      // 加载post_callback
    blr x16
    ret

_twojump_end: