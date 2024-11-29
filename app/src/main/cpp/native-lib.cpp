#include <jni.h>
#include <string>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>
#include <cstdint>
#include <vector>
#include <android/log.h>

#define LOG_TAG "jiqiu2021"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#include <map>
#include <mutex>

#define SH_UTIL_GET_BITS_32(x, start, end) \
  (((x) >> (end)) & ((1u << ((start) - (end) + 1u)) - 1u))

#define SH_UTIL_SIGN_EXTEND_64(x, len) \
  (((int64_t)((x) << (64u - (len)))) >> (64u - (len)))


// 增加寄存器结构体定义
struct RegisterContext {
    uint64_t x[31];    // X0-X30
    uint64_t sp;       // Stack Pointer
    uint64_t pc;       // Program Counter
    uint64_t pstate;   // Processor State
};
enum class ARM64_INS_TYPE {
    UNKNOW,
    ADR,        // 形如 ADR Xd, label
    ADRP,       // 形如 ADRP Xd, label
    B,          // 形如 B label
    BL,         // 形如 BL label
    B_COND,     // 形如 B.cond label
    CBZ_CBNZ,   // 形如 CBZ/CBNZ Rt, label
    TBZ_TBNZ,   // 形如 TBZ/TBNZ Rt, #imm, label
    LDR_LIT,    // 形如 LDR Rt, label
};

// 指令修复器
class ARM64Fixer {
public:
    static size_t
    fix_instructions(uint32_t *orig_code, size_t length, void *orig_addr, void *backup_addr) {
        size_t current_offset = 0;

        // 遍历原始指令
        for (size_t i = 0; i < length / 4; i++) {
            uint32_t ins = orig_code[i];
            void *cur_old_addr = (void *) ((uintptr_t) orig_addr + i * 4);
            void *cur_new_addr = (void *) ((uintptr_t) backup_addr + current_offset);

            // 记录当前指令信息
            LOGI("Processing instruction[%zu]: 0x%08x at old_addr: %p, new_addr: %p",
                 i, ins, cur_old_addr, cur_new_addr);

            // 直接写入到backup_addr对应位置
            current_offset += fix_instruction(
                    (uint32_t *) ((uintptr_t) backup_addr + current_offset),
                    ins, cur_old_addr, cur_new_addr);
        }

        return current_offset; // 返回实际写入的总大小
    }

    static ARM64_INS_TYPE get_ins_type(uint32_t ins) {
        if ((ins & 0x9F000000) == 0x10000000) return ARM64_INS_TYPE::ADR;
        if ((ins & 0x9F000000) == 0x90000000) return ARM64_INS_TYPE::ADRP;
        if ((ins & 0xFC000000) == 0x14000000) return ARM64_INS_TYPE::B;
        if ((ins & 0xFC000000) == 0x94000000) return ARM64_INS_TYPE::BL;
        if ((ins & 0xFF000010) == 0x54000000) return ARM64_INS_TYPE::B_COND;
        if ((ins & 0x7E000000) == 0x34000000) return ARM64_INS_TYPE::CBZ_CBNZ;  // 包括CBZ/CBNZ
        if ((ins & 0x7E000000) == 0x36000000) return ARM64_INS_TYPE::TBZ_TBNZ;  // 包括TBZ/TBNZ
        if ((ins & 0xFF000000) == 0x18000000) return ARM64_INS_TYPE::LDR_LIT;   // LDR (literal) 32位
        if ((ins & 0xFF000000) == 0x58000000) return ARM64_INS_TYPE::LDR_LIT;   // LDR (literal) 64位
        if ((ins & 0xFF000000) == 0x98000000) return ARM64_INS_TYPE::LDR_LIT;   // LDRSW (literal)
        if ((ins & 0xFF000000) == 0x1C000000)
            return ARM64_INS_TYPE::LDR_LIT;   // LDR SIMD (literal) 32位
        if ((ins & 0xFF000000) == 0x5C000000)
            return ARM64_INS_TYPE::LDR_LIT;   // LDR SIMD (literal) 64位
        if ((ins & 0xFF000000) == 0x9C000000)
            return ARM64_INS_TYPE::LDR_LIT;   // LDR SIMD (literal) 128位
        return ARM64_INS_TYPE::UNKNOW;
    }

private:
    // 修改为返回处理后指令占用的字节数
    static size_t fix_instruction(uint32_t *out_ptr, uint32_t ins, void *old_addr, void *new_addr) {
        ARM64_INS_TYPE type = get_ins_type(ins);
        switch (type) {
            case ARM64_INS_TYPE::ADR:
                return fix_adr(out_ptr, ins, old_addr, new_addr);
            case ARM64_INS_TYPE::ADRP:
                return fix_adrp(out_ptr, ins, old_addr, new_addr);
            case ARM64_INS_TYPE::B:
                return fix_b(out_ptr, ins, old_addr, new_addr);
            case ARM64_INS_TYPE::BL:
                return fix_bl(out_ptr, ins, old_addr, new_addr);
            case ARM64_INS_TYPE::B_COND:
                return fix_b_cond(out_ptr, ins, old_addr, new_addr);
            case ARM64_INS_TYPE::CBZ_CBNZ:
                return fix_cbz_cbnz(out_ptr, ins, old_addr, new_addr);
            case ARM64_INS_TYPE::TBZ_TBNZ:
                return fix_tbz_tbnz(out_ptr, ins, old_addr, new_addr);
            case ARM64_INS_TYPE::LDR_LIT:
                return fix_ldr(out_ptr, ins, old_addr, new_addr);
            default:
                *out_ptr = ins;
                return 4;
        }
    }

    // 修复CBZ/CBNZ指令
    static size_t fix_cbz_cbnz(uint32_t *out_ptr, uint32_t ins, void *old_addr, void *new_addr) {
        uint64_t pc = (uint64_t) old_addr;

        // 获取跳转偏移和目标寄存器
        uint64_t imm19 = SH_UTIL_GET_BITS_32(ins, 23, 5);
        uint64_t offset = SH_UTIL_SIGN_EXTEND_64((imm19 << 2u), 21u);
        uint64_t addr = pc + offset;

        // 生成指令序列
        out_ptr[0] = (ins & 0xFF00001F) | 0x40u;  // CB(N)Z Rt, #8  - 保持原有条件但改变偏移
        out_ptr[1] = 0x14000005;                   // B #20          - 跳过加载地址部分
        out_ptr[2] = 0x58000051;                   // LDR X17, #8    - 加载目标地址
        out_ptr[3] = 0xd61f0220;                   // BR X17         - 跳转到目标地址
        out_ptr[4] = addr & 0xFFFFFFFF;            // 目标地址低32位
        out_ptr[5] = addr >> 32u;                  // 目标地址高32位

        return 24;  // 6条指令
    }

// 修复TBZ/TBNZ指令
    static size_t fix_tbz_tbnz(uint32_t *out_ptr, uint32_t ins, void *old_addr, void *new_addr) {
        uint64_t pc = (uint64_t) old_addr;

        // 获取位测试位置和偏移
        uint64_t imm14 = SH_UTIL_GET_BITS_32(ins, 18, 5);
        uint64_t offset = SH_UTIL_SIGN_EXTEND_64((imm14 << 2u), 16u);
        uint64_t addr = pc + offset;

        // 生成指令序列
        out_ptr[0] = (ins & 0xFFF8001F) | 0x40u;  // TB(N)Z Rt, #<imm>, #8 - 保持原有条件和测试位
        out_ptr[1] = 0x14000005;                   // B #20
        out_ptr[2] = 0x58000051;                   // LDR X17, #8
        out_ptr[3] = 0xd61f0220;                   // BR X17
        out_ptr[4] = addr & 0xFFFFFFFF;
        out_ptr[5] = addr >> 32u;

        return 24;  // 6条指令
    }

    static size_t fix_adrp(uint32_t *out_ptr, uint32_t ins, void *old_addr, void *new_addr) {
        uint64_t pc = (uint64_t) old_addr;

        // 获取目标寄存器和立即数
        uint32_t rd = SH_UTIL_GET_BITS_32(ins, 4, 0);  // 目标寄存器
        uint64_t immlo = SH_UTIL_GET_BITS_32(ins, 30, 29);  // 低2位
        uint64_t immhi = SH_UTIL_GET_BITS_32(ins, 23, 5);   // 高19位
        uint64_t offset = SH_UTIL_SIGN_EXTEND_64((immhi << 14u) | (immlo << 12u), 33u);

        // 计算目标页地址
        uint64_t addr = (pc & 0xFFFFFFFFFFFFF000) + offset;

        // 生成新的LDR序列
        out_ptr[0] = 0x58000040u | rd;  // LDR Xd, #8
        out_ptr[1] = 0x14000003;        // B #12
        out_ptr[2] = addr & 0xFFFFFFFF;  // 低32位
        out_ptr[3] = addr >> 32u;        // 高32位

        return 16;  // 4条指令
    }

    static size_t fix_b_cond(uint32_t *out_ptr, uint32_t ins, void *old_addr, void *new_addr) {
        LOGE("B_COND_ARM64");
        uint64_t pc = (uint64_t) old_addr;
        // 获取imm19，5~23位
        uint64_t imm19 = SH_UTIL_GET_BITS_32(ins, 23, 5);
        uint64_t offset = SH_UTIL_SIGN_EXTEND_64((imm19 << 2u), 21u);
        uint64_t addr = pc + offset;

        // 生成新的指令序列
        out_ptr[0] = (ins & 0xFF00001F) | 0x40u;  // B.<cond> #8
        out_ptr[1] = 0x14000006;                  // B #24
        out_ptr[2] = 0x58000051;                  // LDR X17, #8
        out_ptr[3] = 0xd61f0220;                  // BR X17
        out_ptr[4] = addr & 0xFFFFFFFF;
        out_ptr[5] = addr >> 32u;

        return 24;  // 6条指令
    }

    static size_t fix_b(uint32_t *out_ptr, uint32_t ins, void *old_addr, void *new_addr) {
        uint64_t pc = (uint64_t) old_addr;
        uint64_t imm26 = SH_UTIL_GET_BITS_32(ins, 25, 0);
        uint64_t offset = SH_UTIL_SIGN_EXTEND_64(imm26 << 2u, 28u);
        uint64_t addr = pc + offset;

        // 生成指令序列
        out_ptr[0] = 0x58000051;  // LDR X17, #8
        out_ptr[1] = 0x14000003;  // B #12
        out_ptr[2] = addr & 0xFFFFFFFF;
        out_ptr[3] = addr >> 32u;
        out_ptr[4] = 0xD61F0220;  // BR X17

        return 20;  // 5条指令
    }

    static size_t fix_bl(uint32_t *out_ptr, uint32_t ins, void *old_addr, void *new_addr) {
        uint64_t pc = (uint64_t) old_addr;
        uint64_t imm26 = SH_UTIL_GET_BITS_32(ins, 25, 0);
        uint64_t offset = SH_UTIL_SIGN_EXTEND_64(imm26 << 2u, 28u);
        uint64_t addr = pc + offset;

        out_ptr[0] = 0x58000051;  // LDR X17, #8
        out_ptr[1] = 0x14000003;  // B #12
        out_ptr[2] = addr & 0xFFFFFFFF;
        out_ptr[3] = addr >> 32u;
        out_ptr[4] = 0xD63F0220;  // BLR X17

        return 20;
    }

    static size_t fix_adr(uint32_t *out_ptr, uint32_t ins, void *old_addr, void *new_addr) {
        uint64_t pc = (uint64_t) old_addr;
        uint32_t rd = SH_UTIL_GET_BITS_32(ins, 4, 0);
        uint64_t immlo = SH_UTIL_GET_BITS_32(ins, 30, 29);
        uint64_t immhi = SH_UTIL_GET_BITS_32(ins, 23, 5);
        uint64_t addr = pc + SH_UTIL_SIGN_EXTEND_64((immhi << 2u) | immlo, 21u);

        out_ptr[0] = 0x58000040u | rd;  // LDR Xd, #8
        out_ptr[1] = 0x14000003;        // B #12
        out_ptr[2] = addr & 0xFFFFFFFF;
        out_ptr[3] = addr >> 32u;

        return 16;
    }

    static size_t fix_ldr(uint32_t *out_ptr, uint32_t ins, void *old_addr, void *new_addr) {
        uint64_t pc = (uint64_t) old_addr;
        uint32_t rt = SH_UTIL_GET_BITS_32(ins, 4, 0);
        uint32_t rn = 0;
        // 找一个未使用的寄存器
        for (int i = 0; i < 31; i++) {
            if (i != rt) {
                rn = i;
                break;
            }
        }

        uint64_t imm19 = SH_UTIL_GET_BITS_32(ins, 23, 5);
        uint64_t offset = SH_UTIL_SIGN_EXTEND_64((imm19 << 2u), 21u);
        uint64_t addr = pc + offset;

        if ((ins & 0xFF000000) == 0x58000000) {
            // LDR X类指令
            out_ptr[0] = 0x58000060u | rt;  // LDR Xt, #12
            out_ptr[1] = 0xF9400000 | rt | (rt << 5u);  // LDR Xt, [Xt]
            out_ptr[2] = 0x14000003;      // B #12
            out_ptr[3] = addr & 0xFFFFFFFF;
            out_ptr[4] = addr >> 32u;
            return 20;
        } else {
            // LDR S/D/Q类指令
            out_ptr[0] = 0xA93F47F0;  // STP X16, X17, [SP, #-0x10]
            out_ptr[1] = 0x58000091;  // LDR X17, #16
            if ((ins & 0xFF000000) == 0x1C000000)
                out_ptr[2] = 0xBD400220 | rt;  // LDR St, [X17]
            else if ((ins & 0xFF000000) == 0x5C000000)
                out_ptr[2] = 0xFD400220 | rt;  // LDR Dt, [X17]
            else
                out_ptr[2] = 0x3DC00220u | rt;  // LDR Qt, [X17]
            out_ptr[3] = 0xF85F83F1;  // LDR X17, [SP, #-0x8]
            out_ptr[4] = 0x14000003;  // B #12
            out_ptr[5] = addr & 0xFFFFFFFF;
            out_ptr[6] = addr >> 32u;
            return 28;
        }
    }


};

// 函数指针类型定义
typedef void (*func_t)();


struct HookInfo {
    void *target_func;
    void *hook_func;
    void *backup_func;
    uint8_t original_code[1024];
    size_t original_code_size;
    size_t total_size;

    // 增加寄存器回调函数指针
    void (*pre_callback)(RegisterContext *ctx, void *user_data);

    // 执行后回调，增加返回值参数
    void (*post_callback)(RegisterContext *ctx, uint64_t return_value, void *user_data);

    void *user_data;  // 用户自定义数据
};

static thread_local HookInfo *current_executing_hook = nullptr;

// 全局存储所有hook信息
class HookManager {
private:
    static std::map<void *, HookInfo *> hook_map; // key是目标函数地址
    static std::mutex hook_mutex;

public:
    static void registerHook(HookInfo *info) {
        if (!info) return;
        setCurrentHook(info);
        std::lock_guard<std::mutex> lock(hook_mutex);
        hook_map[info->target_func] = info;
    }

    static void setCurrentHook(HookInfo *info) {
        current_executing_hook = info;
    }

    static HookInfo *getCurrentHook() {
        return current_executing_hook;
    }

    static HookInfo *getHook(void *target_func) {
        std::lock_guard<std::mutex> lock(hook_mutex);
        auto it = hook_map.find(target_func);
        return (it != hook_map.end()) ? it->second : nullptr;
    }

    static void removeHook(void *target_func) {
        std::lock_guard<std::mutex> lock(hook_mutex);
        hook_map.erase(target_func);
    }
};

// 初始化静态成员
std::map<void *, HookInfo *> HookManager::hook_map;
std::mutex HookManager::hook_mutex;

inline bool is_addr_valid(void *addr) {
    return addr && ((uintptr_t) addr % 4 == 0);  // ARM64指令必须4字节对齐
}

inline void clear_cache(void *addr, size_t size) {
    __builtin___clear_cache((char *) addr, (char *) addr + size);
}


uint64_t test(int a, int b, int c) {
    LOGI("Test function called");
    LOGI("%d,%d,%d", a, b, c);
    return 0x12345;
}

void hook() {
    RegisterContext ctx;
    asm volatile(
            "stp x0, x1, [%0, #0]\n"
            "stp x2, x3, [%0, #16]\n"
            "stp x4, x5, [%0, #32]\n"
            "stp x6, x7, [%0, #48]\n"
            "stp x8, x9, [%0, #64]\n"
            "stp x10, x11, [%0, #80]\n"
            "stp x12, x13, [%0, #96]\n"
            "stp x14, x15, [%0, #112]\n"
            "stp x16, x17, [%0, #128]\n"
            "stp x18, x19, [%0, #144]\n"
            "stp x20, x21, [%0, #160]\n"
            "stp x22, x23, [%0, #176]\n"
            "stp x24, x25, [%0, #192]\n"
            "stp x26, x27, [%0, #208]\n"
            "stp x28, x29, [%0, #224]\n"
            "str x30, [%0, #240]\n"
            "mov x16, sp\n"
            "str x16, [%0, #248]\n"
            : : "r"(&ctx.x[0]) : "x16", "memory"
            );
    LOGI("Hook function called");
    // 获取 hook 信息
    HookInfo *info = HookManager::getCurrentHook();
    if (info) {
        // 调用寄存器回调函数
        // 获取当前上下文
        // 通过内联汇编获取寄存器值

        if (info->pre_callback) {
            info->pre_callback(&ctx, info->user_data);
        }
        // 调用原始函数并保存返回值
        uint64_t return_value = 0;
        // 调用原始函数
        if (info->backup_func) {
            asm volatile(
                    "ldp x0, x1, [%0, #0]\n"
                    "ldp x2, x3, [%0, #16]\n"
                    "ldp x4, x5, [%0, #32]\n"
                    "ldp x6, x7, [%0, #48]\n"
                    "ldp x8, x9, [%0, #64]\n"
                    "ldp x10, x11, [%0, #80]\n"
                    "ldp x12, x13, [%0, #96]\n"
                    "ldp x14, x15, [%0, #112]\n"
                    "ldp x16, x17, [%0, #128]\n"
                    "ldp x18, x19, [%0, #144]\n"
                    "ldp x20, x21, [%0, #160]\n"
                    "ldp x22, x23, [%0, #176]\n"
                    "ldp x24, x25, [%0, #192]\n"
                    "ldp x26, x27, [%0, #208]\n"
                    "ldp x28, x29, [%0, #224]\n"
                    "ldr x30, [%0, #240]\n"
                    "ldr x16, [%0, #248]\n"
                    "mov sp, x16\n"  // 恢复栈指针
                    ::"r"(&ctx.x[0]) : "memory"
                    );
            ((void (*)()) info->backup_func)();
            RegisterContext post_ctx;
            // 通过内联汇编获取寄存器值
            asm volatile(
                    "stp x0, x1, [%0, #0]\n"
                    "stp x2, x3, [%0, #16]\n"
                    "stp x4, x5, [%0, #32]\n"
                    "stp x6, x7, [%0, #48]\n"
                    "stp x8, x9, [%0, #64]\n"
                    "stp x10, x11, [%0, #80]\n"
                    "stp x12, x13, [%0, #96]\n"
                    "stp x14, x15, [%0, #112]\n"
                    "stp x16, x17, [%0, #128]\n"
                    "stp x18, x19, [%0, #144]\n"
                    "stp x20, x21, [%0, #160]\n"
                    "stp x22, x23, [%0, #176]\n"
                    "stp x24, x25, [%0, #192]\n"
                    "stp x26, x27, [%0, #208]\n"
                    "stp x28, x29, [%0, #224]\n"
                    "str x30, [%0, #240]\n"
                    "mov x16, sp\n"
                    "str x16, [%0, #248]\n"
                    : : "r"(&ctx.x[0]) : "x16", "memory"
                    );
            return_value = post_ctx.x[0];
            // 执行后回调
            if (info->post_callback) {
                info->post_callback(&post_ctx, return_value, info->user_data);
            }
        }
    }
}

bool backup_orig_instructions(HookInfo *info) {
    if (!info || !info->target_func) return false;

    info->original_code_size = 16;
    memcpy(info->original_code, info->target_func, info->original_code_size);

    return true;
}

bool create_jump(void *from, void *to, bool thumb) {
    static const size_t JUMP_SIZE = 16;

    uint32_t jump_code[] = {
            0x58000051,  // ldr x17, #8
            0xD61F0220,  // br x17
            (uint32_t) ((uint64_t) to & 0xFFFFFFFF),
            (uint32_t) ((uint64_t) to >> 32)
    };

    // 修改内存权限
    size_t page_size = sysconf(_SC_PAGESIZE);
    void *page_start = (void *) ((uintptr_t) from & ~(page_size - 1));
    if (mprotect(page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        return false;
    }

    // 写入跳转代码
    memcpy(from, jump_code, sizeof(jump_code));

    // 清理指令缓存
    __builtin___clear_cache((char *) from, (char *) from + sizeof(jump_code));

    return true;
}

// 默认的寄存器打印回调函数
void default_register_callback(RegisterContext *ctx, void *user_data) {
    LOGI("Register dump:");
    for (int i = 0; i < 31; i++) {
        LOGI("X%d: 0x%llx", i, ctx->x[i]);
    }
    LOGI("SP: 0x%llx", ctx->sp);
    LOGI("PC: 0x%llx", ctx->pc);
    LOGI("PSTATE: 0x%llx", ctx->pstate);
}


HookInfo *createHook(void *target_func, void *hook_func,
                     void (*pre_callback)(RegisterContext *, void *) = nullptr,
                     void (*post_callback)(RegisterContext *, uint64_t, void *) = nullptr,
                     void *user_data = nullptr) {
    LOGI("Creating hook - target: %p, hook: %p", target_func, hook_func);
    if (!target_func || !hook_func) return nullptr;
    // 检查是否已经被hook
    HookInfo *existing = HookManager::getHook(target_func);
    if (existing) {
        LOGE("Function already hooked!");
        return nullptr;
    }

    // 创建HookInfo结构
    auto *hookInfo = new HookInfo();
    if (!hookInfo) return nullptr;

    // 初始化结构
    memset(hookInfo, 0, sizeof(HookInfo));
    hookInfo->target_func = target_func;
    hookInfo->hook_func = hook_func;
    hookInfo->pre_callback = pre_callback ? pre_callback : default_register_callback;
    hookInfo->post_callback = post_callback;
    hookInfo->user_data = user_data;
    // 备份原始指令
    if (!backup_orig_instructions(hookInfo)) {
        delete hookInfo;
        return nullptr;
    }

    // 分配跳板内存
    size_t trampoline_size = 256;
    void *trampoline = mmap(nullptr, trampoline_size,
                            PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (trampoline == MAP_FAILED) {
        delete hookInfo;
        return nullptr;
    }
    LOGI("Trampoline allocated at %p", trampoline);

    hookInfo->backup_func = trampoline;

    // 修复指令时记录指令信息
    uint32_t *orig = (uint32_t *) hookInfo->original_code;
    for (size_t i = 0; i < hookInfo->original_code_size / 4; i++) {
        LOGI("Original instruction[%zu]: 0x%08x", i, orig[i]);
    }

    size_t fixed_size = ARM64Fixer::fix_instructions(
            (uint32_t *) hookInfo->original_code,
            hookInfo->original_code_size,
            hookInfo->target_func,
            hookInfo->backup_func
    );
    void *return_addr = (uint8_t *) target_func + hookInfo->original_code_size;
    // 添加跳回原函数的跳转
    if (!create_jump((uint8_t *) hookInfo->backup_func + fixed_size,
                     return_addr, false)) {
        munmap(trampoline, trampoline_size);
        delete hookInfo;
        return nullptr;
    }
    // 在目标函数处写入跳转到hook函数的代码
    if (!create_jump(target_func, hook_func, false)) {
        munmap(trampoline, trampoline_size);
        delete hookInfo;
        return nullptr;
    }
    HookManager::registerHook(hookInfo);
    return hookInfo;
}


bool inline_unhook(HookInfo *info) {
    if (!info) return false;
    HookManager::removeHook(info->target_func);

    // 修改目标函数内存权限
    size_t page_size = sysconf(_SC_PAGESIZE);
    void *page_start = (void *) ((uintptr_t) info->target_func & ~(page_size - 1));
    if (mprotect(page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        return false;
    }

    // 直接恢复原始指令,而不是创建跳转
    memcpy(info->target_func, info->original_code, info->original_code_size);

    // 清理指令缓存
    __builtin___clear_cache((char *) info->target_func,
                            (char *) info->target_func + info->original_code_size);

    // 释放跳板内存
    if (info->backup_func) {
        munmap(info->backup_func, 256);
    }

    delete info;
    return true;
}

// 自定义寄存器回调函数
void my_register_callback(RegisterContext *ctx, void *user_data) {
    LOGI("Custom register dump for function: %s", (const char *) user_data);
    LOGI("X0 (First argument): 0x%llx", ctx->x[0]);
    LOGI("X1 (Second argument): 0x%llx", ctx->x[1]);
    LOGI("LR (X30): 0x%llx", ctx->x[30]);
}

void post_hook_callback(RegisterContext *ctx, uint64_t return_value, void *user_data) {
    LOGI("After function execution:");
    LOGI("Return value: 0x%llx", return_value);
    LOGI("Modified registers: x0=0x%llx, x1=0x%llx", ctx->x[0], ctx->x[1]);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_inlinehookstudy_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
//    __asm__ __volatile__(
//            "b .\n" // 死循环
//            );
    const char *func_name = "test";
    HookInfo *hookInfo = createHook((void *) test, (void *) hook,
                                    nullptr,
                                    post_hook_callback,
                                    (void *) hello.c_str());
    test(1, 2, 3);
    inline_unhook(hookInfo);
//    test();
    return env->NewStringUTF(hello.c_str());
}