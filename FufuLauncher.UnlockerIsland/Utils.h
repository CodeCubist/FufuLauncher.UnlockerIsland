#pragma once
#include <functional>
#include <iostream>

struct Il2CppObject {
    void* klass;
    void* monitor;
};

struct Il2CppString {
    Il2CppObject object;
    int32_t length;
    wchar_t chars[1]; 
};

namespace Detail {
    inline void Runner(void* funcPtr) {
        auto* f = static_cast<std::function<void()>*>(funcPtr);
        (*f)();
    }

    inline void SecureExecutor(void* funcPtr, void (*runner)(void*)) {
        __try {
            runner(funcPtr);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { 
            // OutputDebugStringA("[Utils] SafeInvoke caught a crash!\n");
        }
    }
}

inline void SafeInvoke(std::function<void()> func) {
    Detail::SecureExecutor(&func, Detail::Runner);
}

template <typename T>
bool IsValid(T ptr) {
    if (!ptr) return false;
    return (uintptr_t)ptr > 0x10000 && (uintptr_t)ptr < 0x7FFFFFFFFFFF;
}