.text
.align 2
.global _twojump_start
.global _twojump_end

_twojump_start:
    // 预留16字节存储地址
    .quad 0   // hookinfo 指针
    .quad 0   // hook函数指针

get_data:
    // 使用PC相对寻址
    stp x16, x17, [sp, #-16]!  // 保存x16,x17

    // 获取当前PC值
    mov x16, #0
    bl pc_get
pc_get:
    mov x17, x30  // 获取返回地址(即当前PC)
    mov x30, x16  // 恢复x30

    // 计算基地址
    sub x16, x17, #(pc_get - _twojump_start)

    // 加载hookinfo指针和hook函数指针
    ldp x16, x17, [x16]  // 从基地址加载两个指针

    // 调整基址到 ctx 成员
    add x16, x16, #48    // 新的偏移到 RegisterContext ctx 成员

    // 保存寄存器到 HookInfo->ctx
    ldp x0, x1, [sp], #16  // 恢复x16,x17的值到x0,x1
    stp x0, x1, [x16, #128]  // 保存原始x16,x17
    stp x0, x1, [x16, #0]    // 保存x0,x1 到ctx中
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
    mov x0, sp
    str x0, [x16, #248]   // 保存sp

    // 调用hook函数
    sub x0, x16, #48      // 修改这里,恢复hookinfo指针作为第一个参数
    mov x16, x17          // x17中是hook函数指针
    blr x16              // 调用hook函数

_twojump_end: