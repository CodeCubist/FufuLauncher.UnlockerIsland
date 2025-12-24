#pragma once
#include <Windows.h>

#ifdef MOBILEUIHOOK_EXPORTS
#define MOBILEUIHOOK_API __declspec(dllexport)
#else  
#define MOBILEUIHOOK_API __declspec(dllimport)
#endif

extern "C" {
    MOBILEUIHOOK_API BOOL WINAPI InitializeMobileUIHook(BOOL isGenshin);
    MOBILEUIHOOK_API BOOL WINAPI ShutdownMobileUIHook();
    MOBILEUIHOOK_API BOOL WINAPI GetHookStatus();
    MOBILEUIHOOK_API DWORD WINAPI GetLastErrorCode();
}