#pragma once
#include "pch.h"

#include <Windows.h>
#include <map>
#include <mutex>
#include <cstdio>

#include "MinHook/include/MinHook.h"

#define LOG(fmt, ...) printf("[MinHook] " fmt "\n", ##__VA_ARGS__)
#define ERR(fmt, ...) printf("[MinHook::Error] " fmt "\n", ##__VA_ARGS__)


class MinHookManager {
public:
    struct HookInfo {
        void* target;
        void* hook;
        void** original;
        bool enabled;
    };

private:
    static inline std::once_flag s_initFlag;
    static inline std::map<void*, HookInfo> s_hooks;
    static inline std::mutex s_mutex;

    static void Init() {
        if (MH_Initialize() == MH_OK) {
            LOG("MinHook initialized");
            atexit(&Uninit);
        }
        else {
            ERR("MH_Initialize failed");
        }
    }

    static void Uninit() {
        std::lock_guard<std::mutex> lock(s_mutex);
        for (auto& [target, info] : s_hooks) {
            if (info.enabled)
                MH_DisableHook(target);
            MH_RemoveHook(target);
        }
        s_hooks.clear();
        MH_Uninitialize();
        LOG("MinHook uninitialized");
    }

public:
    static bool Add(void* target, void* hook, void** original) {
        std::call_once(s_initFlag, Init);
        std::lock_guard<std::mutex> lock(s_mutex);

        if (s_hooks.count(target)) {
            ERR("Hook already exists: %p", target);
            return false;
        }

        if (MH_CreateHook(target, hook, original) != MH_OK) {
            ERR("CreateHook failed at: %p", target);
            return false;
        }

        if (MH_EnableHook(target) != MH_OK) {
            MH_RemoveHook(target);
            ERR("EnableHook failed at: %p", target);
            return false;
        }

        s_hooks[target] = { target, hook, original, true };
        LOG("Hook installed: %p -> %p", target, hook);
        return true;
    }

    static bool Remove(void* target) {
        std::lock_guard<std::mutex> lock(s_mutex);
        auto it = s_hooks.find(target);
        if (it == s_hooks.end()) {
            ERR("No such hook: %p", target);
            return false;
        }

        if (it->second.enabled)
            MH_DisableHook(target);
        MH_RemoveHook(target);
        s_hooks.erase(it);
        LOG("Hook removed: %p", target);
        return true;
    }

    static bool Enable(void* target) {
        std::lock_guard<std::mutex> lock(s_mutex);
        auto it = s_hooks.find(target);
        if (it == s_hooks.end()) return false;

        if (!it->second.enabled && MH_EnableHook(target) == MH_OK) {
            it->second.enabled = true;
            LOG("Hook enabled: %p", target);
            return true;
        }
        return false;
    }

    static bool Disable(void* target) {
        std::lock_guard<std::mutex> lock(s_mutex);
        auto it = s_hooks.find(target);
        if (it == s_hooks.end()) return false;

        if (it->second.enabled && MH_DisableHook(target) == MH_OK) {
            it->second.enabled = false;
            LOG("Hook disabled: %p", target);
            return true;
        }
        return false;
    }

    // 一键禁用所有 Hook（Disable）
    static bool DisableAllHooks() {
        MH_STATUS status = MH_DisableHook(MH_ALL_HOOKS);
        return (status == MH_OK);
    }

    // 一键启用所有 Hook（Enable）
    static bool EnableAllHooks() {
        MH_STATUS status = MH_EnableHook(MH_ALL_HOOKS);
        return (status == MH_OK);
    }

};
