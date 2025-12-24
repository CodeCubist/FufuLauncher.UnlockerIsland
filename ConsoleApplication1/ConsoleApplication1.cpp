#include "MobileUIHook.h"
#include <cstdint>
#include <vector>
#include <string>
#include <atomic>
#include <Psapi.h>

// 全局变量
std::atomic<bool> g_IsHooked{false};
DWORD g_LastError = 0;

// 查找模式的内存扫描函数
__declspec(noinline) uintptr_t PatternScanRegion(uintptr_t startAddress, size_t regionSize, const char* pattern) {
    const char* pat = pattern;
    uintptr_t firstMatch = 0;
    
    for (uintptr_t pCur = startAddress; pCur < startAddress + regionSize; ++pCur) {
        if (!*pat) return firstMatch;
        
        if (*(BYTE*)pat == '\?' || *(BYTE*)pCur == getByte(pat)) {
            if (!firstMatch) firstMatch = pCur;
            if (!pat[2]) return firstMatch;
            
            if (*(WORD*)pat == '\?\?' || *(BYTE*)pat != '\?') 
                pat += 3;
            else 
                pat += 2;
        } else {
            pat = pattern;
            firstMatch = 0;
        }
    }
    return 0;
}

// 辅助函数
BYTE getByte(const char*& pattern) {
    if (*pattern == '\?') {
        pattern += (*++pattern == '\?') ? 2 : 1;
        return 0;
    }
    
    BYTE byte = (BYTE)(getHex(*pattern) << 4 | getHex(*(pattern + 1)));
    pattern += 2;
    return byte;
}

BYTE getHex(char c) {
    return (c >= '0' && c <= '9') ? c - '0' : (c & 0xDF) - 'A' + 10;
}

// Genshin Impact 移动UI Hook实现
BOOL HookGenshinMobileUI() {
    HMODULE hUserAssembly = GetModuleHandleA("UserAssembly.dll");
    if (!hUserAssembly) {
        g_LastError = GetLastError();
        return FALSE;
    }

    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hUserAssembly, &modInfo, sizeof(modInfo))) {
        g_LastError = GetLastError();
        return FALSE;
    }

    // 查找移动UI相关函数模式
    uintptr_t patternAddr = PatternScanRegion((uintptr_t)modInfo.lpBaseOfDll, modInfo.SizeOfImage,
        "48 8B 05 ?? ?? ?? ?? 48 8B 88 ?? ?? ?? ?? 48 85 C9 0F ?? ?? ?? ?? ?? BA 02 00 00 00 E8 ?? ?? ?? ?? 48 89 F9 BA 03 00 00 00 E8");

    if (!patternAddr) {
        g_LastError = ERROR_NOT_FOUND;
        return FALSE;
    }

    // 应用Hook
    DWORD oldProtect;
    if (!VirtualProtect((LPVOID)patternAddr, 32, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        g_LastError = GetLastError();
        return FALSE;
    }

    // 修改指令启用移动UI
    BYTE patch[] = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0x90 }; // mov eax, 1; nop
    memcpy((void*)patternAddr, patch, sizeof(patch));

    VirtualProtect((LPVOID)patternAddr, 32, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), (LPVOID)patternAddr, 32);

    return TRUE;
}

// Honkai Star Rail 移动UI Hook实现  
BOOL HookStarRailMobileUI() {
    HMODULE hGameAssembly = GetModuleHandleA("GameAssembly.dll");
    if (!hGameAssembly) {
        g_LastError = GetLastError();
        return FALSE;
    }

    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hGameAssembly, &modInfo, sizeof(modInfo))) {
        g_LastError = GetLastError();
        return FALSE;
    }

    // 查找Star Rail移动UI模式
    uintptr_t patternAddr = PatternScanRegion((uintptr_t)modInfo.lpBaseOfDll, modInfo.SizeOfImage,
        "80 B9 ?? ?? ?? ?? 00 0F 84 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 03 00 00 00 48 83 C4 20 5E C3");

    if (!patternAddr) {
        g_LastError = ERROR_NOT_FOUND;
        return FALSE;
    }

    // 应用Hook - 修改比较指令
    DWORD oldProtect;
    if (!VirtualProtect((LPVOID)(patternAddr + 6), 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        g_LastError = GetLastError();
        return FALSE;
    }

    // 修改为启用移动UI
    *(BYTE*)(patternAddr + 6) = 0x01; // 从 0x00 改为 0x01

    VirtualProtect((LPVOID)(patternAddr + 6), 1, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), (LPVOID)(patternAddr + 6), 1);

    return TRUE;
}

// 通用UI设置函数Hook
BOOL HookUISettings() {
    HMODULE hUnityPlayer = GetModuleHandleA("UnityPlayer.dll");
    if (!hUnityPlayer) return FALSE;

    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hUnityPlayer, &modInfo, sizeof(modInfo))) {
        return FALSE;
    }

    // 查找UI设置相关函数
    uintptr_t uiSettingAddr = PatternScanRegion((uintptr_t)modInfo.lpBaseOfDll, modInfo.SizeOfImage,
        "C7 05 ?? ?? ?? ?? 00 00 00 00 48 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0");

    if (uiSettingAddr) {
        DWORD oldProtect;
        VirtualProtect((LPVOID)uiSettingAddr, 32, PAGE_EXECUTE_READWRITE, &oldProtect);
        
        // 强制启用移动平台设置
        BYTE patch[] = { 0xC7, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 }; // 修改为1
        memcpy((void*)(uiSettingAddr + 6), patch + 6, 4);
        
        VirtualProtect((LPVOID)uiSettingAddr, 32, oldProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(), (LPVOID)uiSettingAddr, 32);
    }

    return TRUE;
}

// 主Hook函数
BOOL InitializeMobileUIHook(BOOL isGenshin) {
    if (g_IsHooked) return TRUE;

    BOOL result = FALSE;
    
    if (isGenshin) {
        result = HookGenshinMobileUI();
    } else {
        result = HookStarRailMobileUI();
    }

    // 应用通用UI设置
    if (result) {
        HookUISettings();
    }

    g_IsHooked = result;
    return result;
}

// 清理函数
BOOL ShutdownMobileUIHook() {
    // 注意：由于是直接内存修改，恢复比较复杂
    // 在实际使用中通常不需要恢复
    g_IsHooked = false;
    return TRUE;
}

// 状态查询
BOOL GetHookStatus() {
    return g_IsHooked;
}

// 错误代码
DWORD GetLastErrorCode() {
    return g_LastError;
}

// DLL入口点
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        break;
        
    case DLL_PROCESS_DETACH:
        ShutdownMobileUIHook();
        break;
    }
    return TRUE;
}