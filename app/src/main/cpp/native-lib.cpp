#include <jni.h>
#include <string>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>
#include <cstdint>
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
    static uint32_t* fix_instructions(uint32_t* orig_code, size_t length, void* orig_addr, void* new_addr) {
        uint32_t* fixed_code = new uint32_t[length/4];
        memcpy(fixed_code, orig_code, length);

        for(size_t i = 0; i < length/4; i++) {
            fix_instruction(&fixed_code[i], (void*)((uintptr_t)orig_addr + i*4), new_addr);
        }
        return fixed_code;
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

    static void fix_instruction(uint32_t* ins_ptr, void* old_addr, void* new_addr) {
        uint32_t ins = *ins_ptr;
        ARM64_INS_TYPE type = get_ins_type(ins);

        switch(type) {
            case ARM64_INS_TYPE::ADR:
                fix_adr(ins_ptr, old_addr, new_addr);
                break;
            case ARM64_INS_TYPE::ADRP:
                fix_adrp(ins_ptr, old_addr, new_addr);
                break;
            case ARM64_INS_TYPE::LDR_LIT:
                fix_ldr_literal(ins_ptr, old_addr, new_addr);
                break;
            default:
                break;
        }
    }

    static void fix_adr(uint32_t* ins_ptr, void* old_addr, void* new_addr) {
        uint32_t ins = *ins_ptr;
        int64_t offset = ((ins >> 5) & 0x7FFFF) << 2;
        if (ins & (1 << 23)) offset |= (0xFFFFFFFFFFFFF800);

        uint64_t target = (uint64_t)old_addr + offset;
        int64_t new_offset = target - (uint64_t)new_addr;

        // 生成新的ADR指令
        uint32_t new_ins = (ins & 0x9F00001F); // 保留opcode和寄存器
        new_ins |= ((new_offset >> 2) & 0x7FFFF) << 5;
        *ins_ptr = new_ins;
    }

    static void fix_adrp(uint32_t* ins_ptr, void* old_addr, void* new_addr) {
        uint32_t ins = *ins_ptr;
        uint64_t old_pc = (uint64_t)old_addr;
        uint64_t new_pc = (uint64_t)new_addr;

        // 获取原始目标页地址
        int32_t immhi = (ins >> 5) & 0x7ffff;
        int32_t immlo = (ins >> 29) & 0x3;
        int32_t imm = (immhi << 2) | immlo;
        // 符号扩展
        if(imm & 0x100000) {
            imm |= 0xfff00000;
        }

        uint64_t old_target = (old_pc & ~0xfff) + (imm << 12);
        int64_t new_offset = ((int64_t)old_target - (new_pc & ~0xfff)) >> 12;

        // 检查新偏移是否在范围内
        if(new_offset > 0x100000 || new_offset < -0x100000) {
            LOGE("ADRP offset out of range");
            // 此时应该改用其他方式实现，比如使用字面量加载
            uint32_t new_code[] = {
                    0x58000050,  // LDR X16, #8
                    0x91000210,  // ADD X16, X16, #0
                    *((uint32_t*)&old_target),
                    *((uint32_t*)&old_target + 1)
            };
            memcpy(ins_ptr, new_code, sizeof(new_code));
            return;
        }

        // 生成新的ADRP指令
        uint32_t new_ins = (ins & 0x9F00001F);
        new_ins |= ((new_offset & 0x7FFFF) << 5);
        new_ins |= ((new_offset & 0x180000) << 29);
        *ins_ptr = new_ins;
    }

    static void fix_ldr_literal(uint32_t* ins_ptr, void* old_addr, void* new_addr) {
        uint32_t ins = *ins_ptr;
        int32_t offset = ((ins >> 5) & 0x7FFFF) << 2;
        uint64_t target = (uint64_t)old_addr + offset;
        int64_t new_offset = target - (uint64_t)new_addr;

        // 生成新的LDR指令
        uint32_t new_ins = (ins & 0xFF00001F);
        new_ins |= ((new_offset >> 2) & 0x7FFFF) << 5;
        *ins_ptr = new_ins;
    }
};
// 函数指针类型定义
typedef void (*func_t)();


struct HookInfo{
    void * target_func;
    void * hook_func;
    void* backup_func;
    uint8_t original_code[32];
    size_t original_code_size;
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

    // 分析需要备份的指令长度
    uint32_t* code = (uint32_t*)info->target_func;
    size_t backup_size = 0;
    size_t min_size = 16; // 至少需要备份16字节用于跳转

    // 分析每条指令直到累计长度大于最小备份长度
    while(backup_size < min_size) {
        ARM64_INS_TYPE type = ARM64Fixer::get_ins_type(*code);
        // 特殊处理需要额外空间的指令类型
        if(type == ARM64_INS_TYPE::ADRP) {
            backup_size += 16; // ADRP可能需要被替换为多条指令
        } else {
            backup_size += 4;
        }
        code++;
    }

    info->original_code_size = backup_size;
    memcpy(info->original_code, info->target_func, backup_size);

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
    uint32_t* fixed_code = ARM64Fixer::fix_instructions(
            (uint32_t*)hookInfo->original_code,
            hookInfo->original_code_size,
            hookInfo->target_func,
            hookInfo->backup_func
    );

    // 打印修复后的指令
    for(size_t i = 0; i < hookInfo->original_code_size/4; i++) {
        LOGI("Fixed instruction[%zu]: 0x%08x", i, fixed_code[i]);
    }
    // 构建跳板
    // 复制修复后的指令到跳板
    memcpy(hookInfo->backup_func, fixed_code, hookInfo->original_code_size);
    delete[] fixed_code;
    // 添加跳回原函数的跳转
    void* return_addr = (uint8_t*)target_func + hookInfo->original_code_size;
    if (!create_jump((uint8_t*)trampoline + hookInfo->original_code_size,
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