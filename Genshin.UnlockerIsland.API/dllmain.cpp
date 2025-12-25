#include "pch.h"
#include "PipeServer.h"
#include "GameState.h"
#include <sstream>

Menu_T menu = {};


class XorString {
    static constexpr char key = 0x5F;

public:
    template<size_t N>
    struct EncryptedData {
        char data[N];
    };
    
    template<size_t N>
    static constexpr auto encrypt(const char(&str)[N]) {
        EncryptedData<N> encrypted{};
        for (size_t i = 0; i < N; ++i) {
            encrypted.data[i] = str[i] ^ key;
        }
        return encrypted;
    }
    
    template<size_t N>
    static std::string decrypt(const EncryptedData<N>& encrypted) {
        std::string decrypted;
        decrypted.resize(N - 1);
        for (size_t i = 0; i < N - 1; ++i) {
            decrypted[i] = encrypted.data[i] ^ key;
        }
        return decrypted;
    }
};


namespace encrypted_strings {
    constexpr auto user32_dll = XorString::encrypt("User32.dll");

    // GameUpdate: 游戏主循环
    constexpr auto pattern_GameUpdate = XorString::encrypt("E8 ? ? ? ? 48 8D 4C 24 ? 8B F8 FF 15 ? ? ? ? E8 ? ? ? ?");
    
    // Get_FrameCount: 读取帧数 (关键防护点)
    // 对应 YSR 的 force_fps_code
    constexpr auto pattern_Get_FrameCount = XorString::encrypt("E8 ? ? ? ? 85 C0 7E 0E E8 ? ? ? ? 0F 57 C0 F3 0F 2A C0 EB 08 ?");
    
    // Set_FrameCount: 设置帧数
    constexpr auto pattern_Set_FrameCount = XorString::encrypt("E8 ? ? ? ? E8 ? ? ? ? 83 F8 1F 0F 9C 05 ? ? ? ? 48 8B 05 ? ? ? ? ");
    
    // Set_SyncCount: 垂直同步相关
    constexpr auto pattern_Set_SyncCount = XorString::encrypt("E8 ? ? ? ? E8 ? ? ? ? 89 C6 E8 ? ? ? ? 31 C9 89 F2 49 89 C0 E8 ? ? ? ? 48 89 C6 48 8B 0D ? ? ? ? 80 B9 ? ? ? ? ? 74 47 48 8B 3D ? ? ? ? 48 85 DF 74 4C ");
    
    // ChangeFOV: 修改视场角
    constexpr auto pattern_ChangeFOV = XorString::encrypt("40 53 48 83 EC 60 0F 29 74 24 ? 48 8B D9 0F 28 F1 E8 ? ? ? ? 48 85 C0 0F 84 ? ? ? ? E8 ? ? ? ? 48 8B C8 ");
    
    // DisplayFog: 雾效/虚化相关
    constexpr auto pattern_DisplayFog = XorString::encrypt("0F B6 02 88 01 8B 42 04 89 41 04 F3 0F 10 52 ? F3 0F 10 4A ? F3 0F 10 42 ? 8B 42 08 ");
    
    // Player_Perspective: 角色视角/虚化去除
    constexpr auto pattern_Player_Perspective = XorString::encrypt("E8 ? ? ? ? 48 8B BE ? ? ? ? 80 3D ? ? ? ? ? 0F 85 ? ? ? ? 80 BE ? ? ? ? ? 74 11");
}

namespace GameHook
{
    uintptr_t hGameModule = 0;
    std::string initErrorMsg = "";
    
    typedef int(*GameUpdate_t)(__int64 a1, const char* a2);
    GameUpdate_t g_original_GameUpdate = nullptr;

    typedef int(*HookGet_FrameCount_t)();
    HookGet_FrameCount_t g_original_HookGet_FrameCount = nullptr;

    typedef int(*Set_FrameCount_t)(int value);
    Set_FrameCount_t g_original_Set_FrameCount = nullptr;

    typedef int(*Set_SyncCount_t)(bool value);
    Set_SyncCount_t g_original_Set_SyncCount = nullptr;

    typedef int(*HookChangeFOV_t)(__int64 a1, float a2);
    HookChangeFOV_t g_original_HookChangeFOV = nullptr;

    typedef int(*HookDisplayFog_t)(__int64 a1, __int64 a2);
    HookDisplayFog_t g_original_HookDisplayFog = nullptr;

    typedef void* (*HookPlayer_Perspective_t)(void* RCX, float Display, void* R8);
    HookPlayer_Perspective_t g_original_Player_Perspective = nullptr;
    

    // ==============================================================================
    // 辅助函数
    // ==============================================================================
    bool CheckCursorVisible()
    {
        CURSORINFO cursorInfo = { 0 };
        cursorInfo.cbSize = sizeof(cursorInfo);
        if (GetCursorInfo(&cursorInfo))
        {
            return (cursorInfo.flags & CURSOR_SHOWING) != 0;
        }
        return false;
    }
    
    bool CheckWindowFocused()
    {
        const HWND foregroundWindow = GetForegroundWindow();
        if (!foregroundWindow) return false;
        DWORD foregroundProcessId = 0;
        GetWindowThreadProcessId(foregroundWindow, &foregroundProcessId);
        return foregroundProcessId == GetCurrentProcessId();
    }
    
    // 每帧更新输入状态
    void UpdateInputStates()
    {
        if (!menu.gameWindow || !IsWindow(menu.gameWindow)) {
             if (CheckWindowFocused()) {
                 menu.gameWindow = GetForegroundWindow();
             }
        }
        menu.isFocused = CheckWindowFocused();
        menu.isCursorVisible = CheckCursorVisible();
        menu.isAltPressed = (GetAsyncKeyState(VK_LMENU) & 0x8000) != 0;
        
        menu.fovSmoother.SetSmoothing(menu.fov_smoothing_factor);
    }
    

    __int64 HookGameUpdate(__int64 a1, const char* a2)
    {
        UpdateInputStates();

        // 强制写入 FPS
        if (menu.enable_fps_override && g_original_Set_FrameCount)
        {
            g_original_Set_FrameCount(menu.selected_fps);
        }

        // 强制关闭垂直同步
        if (menu.enable_syncount_override && g_original_Set_SyncCount)
        {
            g_original_Set_SyncCount(false);
        }

        return g_original_GameUpdate(a1, a2);
    }
    
    int HookGet_FrameCount() {
        if (!g_original_HookGet_FrameCount) return 60;
        
        // 游戏可能会检查 Get_FrameCount() > 60 ? Report() : Continue();
        if (menu.enable_fps_override) {
            return 60; 
        }
        
        int ret = g_original_HookGet_FrameCount();
        if (ret >= 60) return 60;
        else if (ret >= 45) return 45;
        else if (ret >= 30) return 30;
        return ret;
    }
    
    __int64 HookChangeFOV(__int64 a1, float gameRequestedFov)
    {
        if (!menu.enable_fov_override)
        {
            menu.fovSmoother.Reset(gameRequestedFov);
            return g_original_HookChangeFOV(a1, gameRequestedFov);
        }

        float targetFov = gameRequestedFov;
        bool isGameplayState = menu.isFocused && (!menu.isCursorVisible || menu.isAltPressed);
        
        bool isCutsceneOrSpecial = (gameRequestedFov <= 31.0f);
        
        if (isCutsceneOrSpecial || !isGameplayState)
        {
            menu.fovSmoother.Reset(gameRequestedFov);
            return g_original_HookChangeFOV(a1, gameRequestedFov);
        }
        
        targetFov = menu.fov_value;
        
        float smoothedFov = menu.fovSmoother.Update(targetFov);
    
        return g_original_HookChangeFOV(a1, smoothedFov);
    }

    __declspec(align(16)) static uint8_t g_fakeFogStruct[64];

    __int64 HookDisplayFog(__int64 a1, __int64 a2)
    {
        if (menu.enable_display_fog_override && a2)
        {
            memcpy(g_fakeFogStruct, (void*)a2, sizeof(g_fakeFogStruct));
            g_fakeFogStruct[0] = 0; // Disable fog flag
            return g_original_HookDisplayFog(a1, (uintptr_t)g_fakeFogStruct);
        }
        return g_original_HookDisplayFog(a1, a2);
    }

    void* HookPlayer_Perspective(void* RCX, float Display, void* R8)
    {
        if (menu.enable_Perspective_override)
        {
            Display = 1.f;
        }
        return g_original_Player_Perspective(RCX, Display, R8);
    }
    
    bool InitHook()
    {
        bool success = true;
        std::stringstream ssError;
        
        hGameModule = (uintptr_t)GetModuleHandleA(NULL);
        int waitCount = 0;
        while (!hGameModule && waitCount < 100) {
            hGameModule = (uintptr_t)GetModuleHandleA(NULL);
            Sleep(100);
            waitCount++;
        }
        if (!hGameModule) {
            initErrorMsg = "Failed to get Game Module Handle.";
            return false;
        }

        menu.fovSmoother.Reset(45.0f);
        
        // Helper macro for error handling
        #define CHECK_ADDR(addr, name) if(!addr) { ssError << name << " Pattern Failed\n"; success = false; }
        #define CHECK_HOOK(status, name) if(status != MH_OK) { ssError << name << " Hook Failed\n"; success = false; }

        // 1. GameUpdate
        void* GameUpdateAddr = (void*)PatternScanner::Scan(XorString::decrypt(encrypted_strings::pattern_GameUpdate));
        if (GameUpdateAddr) {
            GameUpdateAddr = (void*)PatternScanner::ResolveRelativeAddress((uintptr_t)GameUpdateAddr);
            if(MH_CreateHook(GameUpdateAddr, &HookGameUpdate, (void**)&g_original_GameUpdate) != MH_OK) {
                ssError << "GameUpdate CreateHook Failed\n"; success = false;
            }
        } else { CHECK_ADDR(GameUpdateAddr, "GameUpdate"); }

        // 2. Get_FrameCount (Requires double resolve)
        void* Get_FrameCountAddr = (void*)PatternScanner::Scan(XorString::decrypt(encrypted_strings::pattern_Get_FrameCount));
        if (Get_FrameCountAddr) {
            Get_FrameCountAddr = (void*)PatternScanner::ResolveRelativeAddress((uintptr_t)Get_FrameCountAddr);
            Get_FrameCountAddr = (void*)PatternScanner::ResolveRelativeAddress((uintptr_t)Get_FrameCountAddr);
            if(MH_CreateHook(Get_FrameCountAddr, &HookGet_FrameCount, (void**)&g_original_HookGet_FrameCount) != MH_OK) {
                 ssError << "Get_FrameCount CreateHook Failed\n"; success = false;
            }
        } else { CHECK_ADDR(Get_FrameCountAddr, "Get_FrameCount"); }

        // 3. Set_FrameCount (Function Pointer only)
        void* Set_FrameCountAddr = (void*)PatternScanner::Scan(XorString::decrypt(encrypted_strings::pattern_Set_FrameCount));
        if (Set_FrameCountAddr) {
            Set_FrameCountAddr = (void*)PatternScanner::ResolveRelativeAddress((uintptr_t)Set_FrameCountAddr);
            Set_FrameCountAddr = (void*)PatternScanner::ResolveRelativeAddress((uintptr_t)Set_FrameCountAddr);
            g_original_Set_FrameCount = (Set_FrameCount_t)Set_FrameCountAddr;
        } else { CHECK_ADDR(Set_FrameCountAddr, "Set_FrameCount"); }

        // 4. Set_SyncCount (Function Pointer only)
        void* Set_SyncCountAddr = (void*)PatternScanner::Scan(XorString::decrypt(encrypted_strings::pattern_Set_SyncCount));
        if (Set_SyncCountAddr) {
            Set_SyncCountAddr = (void*)PatternScanner::ResolveRelativeAddress((uintptr_t)Set_SyncCountAddr);
            g_original_Set_SyncCount = (Set_SyncCount_t)Set_SyncCountAddr;
        } else { CHECK_ADDR(Set_SyncCountAddr, "Set_SyncCount"); }

        // 5. ChangeFOV
        void* ChangeFOVAddr = (void*)PatternScanner::Scan(XorString::decrypt(encrypted_strings::pattern_ChangeFOV));
        if (ChangeFOVAddr) {
             if(MH_CreateHook(ChangeFOVAddr, &HookChangeFOV, (void**)&g_original_HookChangeFOV) != MH_OK) {
                 ssError << "ChangeFOV CreateHook Failed\n"; success = false;
             }
        } else { CHECK_ADDR(ChangeFOVAddr, "ChangeFOV"); }

        // 6. DisplayFog
        void* DisplayFogAddr = (void*)PatternScanner::Scan(XorString::decrypt(encrypted_strings::pattern_DisplayFog));
        if (DisplayFogAddr) {
             if(MH_CreateHook(DisplayFogAddr, &HookDisplayFog, (void**)&g_original_HookDisplayFog) != MH_OK) {
                 ssError << "DisplayFog CreateHook Failed\n"; success = false;
             }
        } else { CHECK_ADDR(DisplayFogAddr, "DisplayFog"); }

        // 7. Player_Perspective
        void* Player_PerspectiveAddr = (void*)PatternScanner::Scan(XorString::decrypt(encrypted_strings::pattern_Player_Perspective));
        if (Player_PerspectiveAddr) {
            Player_PerspectiveAddr = (void*)PatternScanner::ResolveRelativeAddress((uintptr_t)Player_PerspectiveAddr);
            if(MH_CreateHook(Player_PerspectiveAddr, &HookPlayer_Perspective, (void**)&g_original_Player_Perspective) != MH_OK) {
                 ssError << "Player_Perspective CreateHook Failed\n"; success = false;
            }
        } else { CHECK_ADDR(Player_PerspectiveAddr, "Player_Perspective"); }

        if (!success) {
            initErrorMsg = ssError.str();
        }

        return success;
    }
}

DWORD WINAPI Run(LPVOID lpParam)
{
    // 初始化 MinHook
    if (MH_Initialize() != MH_OK) {
        MessageBoxA(NULL, "MinHook Initialize Failed", "Error", MB_ICONERROR);
        return FALSE;
    }
    
    if (GameHook::InitHook()) {
        if (MH_EnableHook(MH_ALL_HOOKS) == MH_OK) {
            StartPipeServer();
        } else {
            MessageBoxA(NULL, "MH_EnableHook Failed", "Error", MB_ICONERROR);
        }
    } else {
        MessageBoxA(NULL, GameHook::initErrorMsg.c_str(), "Pattern Scan Error", MB_ICONERROR);
    }
    return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, Run, NULL, 0, NULL);
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH)
    {
        StopPipeServer();
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
    }
    return TRUE;
}