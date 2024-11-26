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
// 函数指针类型定义
typedef void (*func_t)();


struct HookInfo{
    void * target_func;
    void * hook_func;
    void* backup_func;
    uint8_t original_code[32];
    size_t original_code_size;
};

// 全局存储所有hook信息
class HookManager {
private:
    static std::map<void*, HookInfo*> hook_map; // key是目标函数地址
    static std::mutex hook_mutex;

public:
    static void registerHook(HookInfo* info) {
        if (!info) return;
        std::lock_guard<std::mutex> lock(hook_mutex);
        hook_map[info->target_func] = info;
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
    void* caller = __builtin_return_address(0);
    // 根据调用地址范围查找对应的HookInfo
    HookInfo* info = HookManager::getHook(caller);

    if(info && info->backup_func) {
        // 调用原始函数
        ((void(*)())info->backup_func)();
    }
}

bool backup_orig_instructions(HookInfo* info) {
    if(!info || !info->target_func) return false;

    // ARM64指令是固定4字节长度
    constexpr size_t MIN_BACKUP_SIZE = 16;  // 至少备份16字节(4条指令)

    // 保存指令
    memcpy(info->original_code, info->target_func, MIN_BACKUP_SIZE);
    info->original_code_size = MIN_BACKUP_SIZE;

    // 解析第一条指令
    uint32_t* code = (uint32_t*)info->target_func;

    // 检查是否是跳转指令
    if ((*code & 0xFC000000) == 0x14000000 ||    // B
        (*code & 0xFC000000) == 0x94000000 ||    // BL
        (*code & 0xFF000000) == 0x54000000) {    // B.cond

        // 如果是跳转指令,我们需要保证备份至少包含完整的跳转指令
        info->original_code_size = 4;
    }

    return true;
}

bool create_jump(void* from, void* to, bool thumb) {
    uint32_t jump_code[4];

    // ARM64跳转指令序列
    jump_code[0] = 0x58000050;  // LDR X16, #8
    jump_code[1] = 0xD61F0200;  // BR X16
    jump_code[2] = (uint64_t)to & 0xFFFFFFFF;
    jump_code[3] = (uint64_t)to >> 32;

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

    hookInfo->backup_func = trampoline;

    // 构建跳板
    memcpy(trampoline, hookInfo->original_code, hookInfo->original_code_size);

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