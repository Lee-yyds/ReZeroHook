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
    static size_t fix_instructions(uint32_t* orig_code, size_t length, void* orig_addr, void* backup_addr) {
        size_t current_offset = 0;

        // 遍历原始指令
        for(size_t i = 0; i < length/4; i++) {
            uint32_t ins = orig_code[i];
            void* cur_old_addr = (void*)((uintptr_t)orig_addr + i*4);
            void* cur_new_addr = (void*)((uintptr_t)backup_addr + current_offset);

            // 记录当前指令信息
            LOGI("Processing instruction[%zu]: 0x%08x at old_addr: %p, new_addr: %p",
                 i, ins, cur_old_addr, cur_new_addr);

            // 直接写入到backup_addr对应位置
            current_offset += fix_instruction((uint32_t*)((uintptr_t)backup_addr + current_offset),
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
        if ((ins & 0x7F000000) == 0x34000000) return ARM64_INS_TYPE::CBZ_CBNZ;
        if ((ins & 0x7F000000) == 0x36000000) return ARM64_INS_TYPE::TBZ_TBNZ;
        if ((ins & 0xFF000000) == 0x58000000) return ARM64_INS_TYPE::LDR_LIT;
        return ARM64_INS_TYPE::UNKNOW;
    }

private:
    // 修改为返回处理后指令占用的字节数
    static size_t fix_instruction(uint32_t* out_ptr, uint32_t ins, void* old_addr, void* new_addr) {
        ARM64_INS_TYPE type = get_ins_type(ins);
        uint64_t pc = (uint64_t)old_addr;
        int trampoline_pos = 0;
        switch(type) {
            case ARM64_INS_TYPE::ADR:
                fix_adr(out_ptr, ins, old_addr, new_addr);
                return 12;
            case ARM64_INS_TYPE::ADRP:
                fix_adrp(out_ptr, ins, old_addr, new_addr);
                return 16; // ADRP被替换为4条指令
            case ARM64_INS_TYPE::LDR_LIT:
                fix_ldr_literal(out_ptr, ins, old_addr, new_addr);
                return 28;
            case ARM64_INS_TYPE::B:
                fix_b(out_ptr, ins, old_addr, new_addr);
                return 20;
            case ARM64_INS_TYPE::BL:
                fix_bl(out_ptr, ins, old_addr, new_addr);
                return 20;  // 5 instructions
            case ARM64_INS_TYPE::B_COND:
                fix_b_cond(out_ptr, ins, old_addr, new_addr);
                return 32;  // 8 instructions
            default:
                *out_ptr = ins; // 直接复制未修改的指令
                return 4;
        }
    }

    // 修改fix_adr等函数的参数，添加原始指令参数
    static void fix_adr(uint32_t* out_ptr, uint32_t ins, void* old_addr, void* new_addr) {
        int64_t offset = ((ins >> 5) & 0x7FFFF) << 2;
        if (ins & (1 << 23)) offset |= (0xFFFFFFFFFFFFF800);

        uint64_t target = (uint64_t)old_addr + offset;
        int64_t new_offset = target - (uint64_t)new_addr;

        // 生成新的ADR指令
        uint32_t new_ins = (ins & 0x9F00001F); // 保留opcode和寄存器
        new_ins |= ((new_offset >> 2) & 0x7FFFF) << 5;
        *out_ptr = new_ins;
    }

    static void fix_adrp(uint32_t* out_ptr, uint32_t ins, void* old_addr, void* new_addr) {
        uint64_t pc = (uint64_t)old_addr;
        LOGI("ADRP_ARM64 fixing");

        // 解析imm21和rd
        uint32_t imm21 = ((ins & 0xFFFFE0)>>3) + ((ins & 0x60000000)>>29);
        uint32_t rd = ins & 0x1F;

        // 计算目标地址
        uint64_t value = (pc & 0xfffffffffffff000) + 4096*imm21;
        if((imm21 & 0x100000)==0x100000) {
            LOGI("NEG");
            value = (pc & 0xfff) - 4096 * (0x1fffff - imm21 + 1);
        }

        // 调试日志
        LOGI("pc    : %lx", pc);
        LOGI("imm21 : %x", imm21);
        LOGI("value : %lx", value);
        LOGI("valueh: %x", (uint32_t)(value >> 32));
        LOGI("valuel: %x", (uint32_t)(value & 0xffffffff));

        // 生成新的指令序列
        uint32_t new_seq[] = {
                0x58000040 + rd,       // ldr rd, 8
                0x14000003,           // b 12
                (uint32_t)(value & 0xffffffff),  // target address low
                (uint32_t)(value >> 32)          // target address high
        };

        // 写入新指令序列
        memcpy(out_ptr, new_seq, sizeof(new_seq));
    }

    static size_t fix_ldr_literal(uint32_t* out_ptr, uint32_t ins, void* old_addr, void* new_addr) {
        LOGI("LDR_ARM64");
        uint64_t pc = (uint64_t)old_addr;
        uint32_t rt = ins & 0x1f;
        uint32_t rn = 0;

        // 找一个未使用的寄存器
        for(int i = 0; i < 31; i++) {
            if(i != rt) {
                rn = i;
                break;
            }
        }
        LOGI("Rn : %d", rn);

        // 计算目标地址
        uint32_t imm19 = ((ins & 0xFFFFE0) >> 5);
        uint64_t value = pc + 4 * imm19;
        if((imm19 & 0x40000) == 0x40000) {
            value = pc - 4 * (0x7ffff - imm19 + 1);
        }

        // 生成新的指令序列
        uint32_t new_seq[] = {
                0xa93f03e0 + rt + (rn << 10),  // STP Xt, Xn, [SP, #-0x10]
                0x58000080 + rn,               // LDR Xn, 16
                0xf9400000 + (rn << 5),        // LDR Xt, [Xn, 0]
                0xf85f83e0 + rn,               // LDR Xn, [sp, #-0x8]
                0x14000002,                    // B 8
                (uint32_t)(value >> 32),
                (uint32_t)(value & 0xffffffff)
        };

        memcpy(out_ptr, new_seq, sizeof(new_seq));
        return sizeof(new_seq);
    }
    static size_t fix_b(uint32_t* out_ptr, uint32_t ins, void* old_addr, void* new_addr) {
        LOGI("B_ARM64");
        uint64_t pc = (uint64_t)old_addr;
        uint32_t imm26 = ins & 0xFFFFFF;
        uint64_t value = pc + imm26 * 4;

        // 生成新的指令序列
        uint32_t new_seq[] = {
                0x5800007E,                    // LDR LR, 12
                0xD63F03C0,                    // BLR LR
                0x14000003,                    // B 12
                (uint32_t)(value & 0xffffffff),
                (uint32_t)(value >> 32)
        };

        memcpy(out_ptr, new_seq, sizeof(new_seq));
        return sizeof(new_seq);
    }

    static size_t fix_bl(uint32_t* out_ptr, uint32_t ins, void* old_addr, void* new_addr) {
        LOGE("BL_ARM64");
        uint64_t pc = (uint64_t)old_addr;
        uint32_t imm26 = ins & 0xFFFFFF;
        uint64_t value;

        if ((ins & 0xFC000000) == 0x94000000) { // 正向跳转
            value = pc + imm26 * 4;
        } else { // 反向跳转
            value = pc - 4 * (0xffffff - imm26 + 1);
        }

        uint32_t new_seq[] = {
                0x5800007E,                    // LDR LR, 12
                0xD63F03C0,                    // BLR LR
                0x14000003,                    // B 12
                (uint32_t)(value & 0xffffffff),
                (uint32_t)(value >> 32)
        };

        memcpy(out_ptr, new_seq, sizeof(new_seq));
        return sizeof(new_seq);
    }

    static size_t fix_b_cond(uint32_t* out_ptr, uint32_t ins, void* old_addr, void* new_addr) {
        LOGE("B_COND_ARM64");
        uint64_t pc = (uint64_t)old_addr;

        uint32_t imm19 = (ins & 0xFFFFE0) >> 5;
        uint64_t value = pc + imm19 * 4;
        if((imm19 >> 18) == 1) {
            value = pc - 4 * (0x7ffff - imm19 + 1);
        }

        // 生成反向条件跳转
        uint32_t new_seq[] = {
                ((ins & 0xff00000f) + (32 << 3)) ^ 0x1,  // B.anti_cond 32
                *((uint32_t*)value),                      // target instruction
                0xa93f03e0,                              // STP X0, X0, [SP, #-0x10]
                0x58000080,                              // LDR X0, 12
                0xd61f0000,                              // BR X0
                0x14000002,                              // B 8
                (uint32_t)(value >> 32),
                (uint32_t)(value & 0xffffffff)
        };

        memcpy(out_ptr, new_seq, sizeof(new_seq));
        return sizeof(new_seq);
    }

};
// 函数指针类型定义
typedef void (*func_t)();


struct HookInfo{
    void * target_func;
    void * hook_func;
    void* backup_func;
    uint8_t original_code[1024];
    size_t original_code_size;
    size_t total_size;
};
static thread_local HookInfo* current_executing_hook = nullptr;

// 全局存储所有hook信息
class HookManager {
private:
    static std::map<void*, HookInfo*> hook_map; // key是目标函数地址
    static std::mutex hook_mutex;

public:
    static void registerHook(HookInfo* info) {
        if (!info) return;
        setCurrentHook(info);
        std::lock_guard<std::mutex> lock(hook_mutex);
        hook_map[info->target_func] = info;
    }
    static void setCurrentHook(HookInfo* info) {
        current_executing_hook = info;
    }

    static HookInfo* getCurrentHook() {
        return current_executing_hook;
    }
    static HookInfo* getHook(void* target_func) {
        std::lock_guard<std::mutex> lock(hook_mutex);
        auto it = hook_map.find(target_func);
        return (it != hook_map.end()) ? it->second : nullptr;
    }

    static void removeHook(void* target_func) {
        std::lock_guard<std::mutex> lock(hook_mutex);
        hook_map.erase(target_func);
    }
};

// 初始化静态成员
std::map<void*, HookInfo*> HookManager::hook_map;
std::mutex HookManager::hook_mutex;
inline bool is_addr_valid(void* addr) {
    return addr && ((uintptr_t)addr % 4 == 0);  // ARM64指令必须4字节对齐
}

inline void clear_cache(void* addr, size_t size) {
    __builtin___clear_cache((char*)addr, (char*)addr + size);
}


void test(){
    LOGI("Test function called");
}

void hook() {
    LOGI("Hook function called");

    // 获取调用者地址
//    void* caller = __builtin_return_address(0);
    // 根据调用地址范围查找对应的HookInfo
    HookInfo* info = HookManager::getCurrentHook();

    if(info && info->backup_func) {
        // 调用原始函数
        ((void(*)())info->backup_func)();
    }
}

bool backup_orig_instructions(HookInfo* info) {
    if(!info || !info->target_func) return false;

    info->original_code_size = 16;
    memcpy(info->original_code, info->target_func, info->original_code_size);

    return true;
}
bool create_jump(void* from, void* to, bool thumb) {
    static const size_t JUMP_SIZE = 16;

    uint32_t jump_code[] = {
            0x58000051,  // ldr x17, #8
            0xD61F0220,  // br x17
            (uint32_t)((uint64_t)to & 0xFFFFFFFF),
            (uint32_t)((uint64_t)to >> 32)
    };

    // 修改内存权限
    size_t page_size = sysconf(_SC_PAGESIZE);
    void* page_start = (void*)((uintptr_t)from & ~(page_size - 1));
    if(mprotect(page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        return false;
    }

    // 写入跳转代码
    memcpy(from, jump_code, sizeof(jump_code));

    // 清理指令缓存
    __builtin___clear_cache((char*)from, (char*)from + sizeof(jump_code));

    return true;
}


HookInfo* createHook(void* target_func, void* hook_func) {
    LOGI("Creating hook - target: %p, hook: %p", target_func, hook_func);
    if(!target_func || !hook_func) return nullptr;
    // 检查是否已经被hook
    HookInfo* existing = HookManager::getHook(target_func);
    if(existing) {
        LOGE("Function already hooked!");
        return nullptr;
    }

    // 创建HookInfo结构
    auto* hookInfo = new HookInfo();
    if(!hookInfo) return nullptr;

    // 初始化结构
    memset(hookInfo, 0, sizeof(HookInfo));
    hookInfo->target_func = target_func;
    hookInfo->hook_func = hook_func;

    // 备份原始指令
    if (!backup_orig_instructions(hookInfo)) {
        delete hookInfo;
        return nullptr;
    }

    // 分配跳板内存
    size_t trampoline_size = 256;
    void* trampoline = mmap(nullptr, trampoline_size,
                            PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (trampoline == MAP_FAILED) {
        delete hookInfo;
        return nullptr;
    }
    LOGI("Trampoline allocated at %p", trampoline);

    hookInfo->backup_func = trampoline;

    // 修复指令时记录指令信息
    uint32_t* orig = (uint32_t*)hookInfo->original_code;
    for(size_t i = 0; i < hookInfo->original_code_size/4; i++) {
        LOGI("Original instruction[%zu]: 0x%08x", i, orig[i]);
    }

    size_t fixed_size = ARM64Fixer::fix_instructions(
            (uint32_t*)hookInfo->original_code,
            hookInfo->original_code_size,
            hookInfo->target_func,
            hookInfo->backup_func
    );
    void* return_addr = (uint8_t*)target_func + hookInfo->original_code_size;
    // 添加跳回原函数的跳转
    if (!create_jump((uint8_t*)hookInfo->backup_func + fixed_size,
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


bool inline_unhook(HookInfo* info) {
    if (!info) return false;
    HookManager::removeHook(info->target_func);

    // 修改目标函数内存权限
    size_t page_size = sysconf(_SC_PAGESIZE);
    void* page_start = (void*)((uintptr_t)info->target_func & ~(page_size - 1));
    if(mprotect(page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        return false;
    }

    // 直接恢复原始指令,而不是创建跳转
    memcpy(info->target_func, info->original_code, info->original_code_size);

    // 清理指令缓存
    __builtin___clear_cache((char*)info->target_func,
                            (char*)info->target_func + info->original_code_size);

    // 释放跳板内存
    if(info->backup_func) {
        munmap(info->backup_func, 256);
    }

    delete info;
    return true;
}
extern "C" JNIEXPORT jstring JNICALL
Java_com_example_inlinehookstudy_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
//    __asm__ __volatile__(
//            "b .\n" // 死循环
//            );

    HookInfo* hookInfo = createHook((void*)test, (void*)hook);
    test();
    inline_unhook(hookInfo);
//    test();
    return env->NewStringUTF(hello.c_str());
}