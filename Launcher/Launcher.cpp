#include <windows.h>
#include <shlwapi.h>
#include <string>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <vector>
#include <random>
#include "Launcher.h"

#pragma comment(lib, "shlwapi.lib")

const wchar_t* MAPPING_NAME = L"4F3E8543-40F7-4808-82DC-21E48A6037A7";
const wchar_t* TEMP_SUBDIR_NAME = L"NV_Cache_Temp"; 

struct SimpleConfig {
    int HideQuestBanner;
    int DisableShowDamageText;
    int UsingTouchScreen;
    int DisableEventCameraMove;
    int RemoveOpenTeamProgress;
    int RedirectCombineEntry;
    int ResinListItemId000106Allowed;
    int ResinListItemId000201Allowed;
    int ResinListItemId107009Allowed;
    int ResinListItemId107012Allowed;
    int ResinListItemId220007Allowed;
} g_LocalConfig = { 0 };

HANDLE g_hMapFile = NULL;
IslandEnvironment* g_pEnv = NULL;

std::wstring GetLogFilePath() {
    wchar_t modulePath[MAX_PATH];
    if (GetModuleFileNameW(nullptr, modulePath, MAX_PATH) == 0) return L"Launcher.log";
    std::wstring moduleDir = modulePath;
    size_t lastSlash = moduleDir.find_last_of(L"\\/");
    if (lastSlash == std::wstring::npos) return L"Launcher.log";
    return moduleDir.substr(0, lastSlash) + L"\\Launcher.log";
}

void WriteLog(const std::string& message) {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::tm tm; localtime_s(&tm, &time_t);
    std::stringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    
    std::ofstream logFile(GetLogFilePath(), std::ios::app);
    if (logFile.is_open()) {
        logFile << "[" << ss.str() << "] " << message << std::endl;
    }
}

void HideConsole() {
    HWND hwnd = GetConsoleWindow();
    if (hwnd != NULL) ShowWindow(hwnd, SW_HIDE);
}

std::wstring GenerateRandomString(size_t length) {
    const std::wstring chars = L"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<size_t> distribution(0, chars.size() - 1);
    std::wstring random_string;
    for (size_t i = 0; i < length; ++i) {
        random_string += chars[distribution(generator)];
    }
    return random_string;
}

std::wstring GetDedicatedTempPath() {
    wchar_t sysTemp[MAX_PATH];
    if (GetTempPathW(MAX_PATH, sysTemp) == 0) return L"";
    
    std::wstring dir = std::wstring(sysTemp) + TEMP_SUBDIR_NAME;
    
    if (GetFileAttributesW(dir.c_str()) == INVALID_FILE_ATTRIBUTES) {
        CreateDirectoryW(dir.c_str(), NULL);
    }
    return dir;
}

void CleanupOldSessions() {
    std::wstring dir = GetDedicatedTempPath();
    if (dir.empty()) return;

    std::wstring searchPath = dir + L"\\*.dll";
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) return;

    int deletedCount = 0;
    int lockedCount = 0;

    do {
        if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            std::wstring fullPath = dir + L"\\" + findData.cFileName;
            if (DeleteFileW(fullPath.c_str())) {
                deletedCount++;
            } else {
                MoveFileExW(fullPath.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
                lockedCount++;
            }
        }
    } while (FindNextFileW(hFind, &findData) != 0);

    FindClose(hFind);

    if (deletedCount > 0 || lockedCount > 0) {
        WriteLog("清理维护: 删除了 " + std::to_string(deletedCount) + " 个旧文件, 标记了 " + std::to_string(lockedCount) + " 个锁定文件待重启删除。");
    }
}

bool ObfuscateFileHash(const std::wstring& filePath) {
    std::ofstream file(filePath, std::ios::binary | std::ios::app);
    if (!file.is_open()) return false;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(2048, 8192);
    std::uniform_int_distribution<> byteDis(0, 255);

    int appendSize = dis(gen);
    std::vector<char> junk(appendSize);
    for (int i = 0; i < appendSize; ++i) junk[i] = static_cast<char>(byteDis(gen));

    file.write(junk.data(), appendSize);
    file.close();
    return true;
}
std::wstring PrepareSafeDll(const std::wstring& originalDllPath) {
    if (GetFileAttributesW(originalDllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        WriteLog("错误: 源文件不存在 " + std::string(originalDllPath.begin(), originalDllPath.end()));
        return L"";
    }

    std::wstring tempDir = GetDedicatedTempPath();
    if (tempDir.empty()) {
        WriteLog("错误: 无法创建或访问临时目录");
        return L"";
    }
    
    std::wstring randomName = GenerateRandomString(12);
    std::wstring targetPath = tempDir + L"\\" + randomName + L".dll";
    
    if (!CopyFileW(originalDllPath.c_str(), targetPath.c_str(), FALSE)) {
        WriteLog("错误: 复制DLL失败 Error=" + std::to_string(GetLastError()));
        return L"";
    }
    
    if (!ObfuscateFileHash(targetPath)) {
        WriteLog("警告: 哈希混淆失败，但将继续使用副本");
    }
    
    if (!MoveFileExW(targetPath.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT)) {

    }

    WriteLog("已生成安全副本: " + std::string(targetPath.begin(), targetPath.end()));
    return targetPath;
}


void InitOffsets(IslandEnvironment* env) {
    if (!env) return;
    memset(env, 0, sizeof(IslandEnvironment));
    env->Size = sizeof(IslandEnvironment);

    env->IslandFunctionOffsets.MickeyWonderMethod = 0x5e0d680;
    env->IslandFunctionOffsets.MickeyWonderMethodPartner = 0x3e87b0;
    env->IslandFunctionOffsets.MickeyWonderMethodPartner2 = 0x7728b90;
    env->IslandFunctionOffsets.SetFieldOfView = 0x10407c0;
    env->IslandFunctionOffsets.SetEnableFogRendering = 0x14f2cb90;
    env->IslandFunctionOffsets.SetTargetFrameRate = 0x14f18ea0;
    env->IslandFunctionOffsets.OpenTeam = 0xb8dcfa0;
    env->IslandFunctionOffsets.OpenTeamPageAccordingly = 0xb8e5fb0;
    env->IslandFunctionOffsets.CheckCanEnter = 0x954f230;
    env->IslandFunctionOffsets.SetupQuestBanner = 0xdbb1320;
    env->IslandFunctionOffsets.FindGameObject = 0x14f1bf20;
    env->IslandFunctionOffsets.SetActive = 0x14f1bc60;
    env->IslandFunctionOffsets.EventCameraMove = 0xe076e80;
    env->IslandFunctionOffsets.ShowOneDamageTextEx = 0xfea2160;
    env->IslandFunctionOffsets.SwitchInputDeviceToTouchScreen = 0xab06670;
    env->IslandFunctionOffsets.MickeyWonderCombineEntryMethod = 0xa0a2d00;
    env->IslandFunctionOffsets.MickeyWonderCombineEntryMethodPartner = 0x84fb720;
    env->IslandFunctionOffsets.GetTargetFrameRate = 0x125a050;
    env->IslandFunctionOffsets.GameManagerAwake = 0xc4007c0;
    
    WriteLog("内存环境初始化完成");
}

void SyncSharedMemory() {
    if (g_hMapFile == NULL) {
        g_hMapFile = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(IslandEnvironment), MAPPING_NAME);
        if (g_hMapFile == NULL) {
            WriteLog("Map创建失败: " + std::to_string(GetLastError()));
            return;
        }
    }
    
    if (g_pEnv == NULL) {
        g_pEnv = (IslandEnvironment*)MapViewOfFile(g_hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
        if (g_pEnv == NULL) {
            WriteLog("View映射失败");
            return;
        }
        InitOffsets(g_pEnv);
    }
    
    if (g_pEnv != NULL) {
        g_pEnv->HideQuestBanner = g_LocalConfig.HideQuestBanner;
        g_pEnv->DisableShowDamageText = g_LocalConfig.DisableShowDamageText;
        g_pEnv->UsingTouchScreen = g_LocalConfig.UsingTouchScreen;
        g_pEnv->DisableEventCameraMove = g_LocalConfig.DisableEventCameraMove;
        g_pEnv->RemoveOpenTeamProgress = g_LocalConfig.RemoveOpenTeamProgress;
        g_pEnv->RedirectCombineEntry = g_LocalConfig.RedirectCombineEntry;
        g_pEnv->ResinListItemId000106Allowed = g_LocalConfig.ResinListItemId000106Allowed;
        g_pEnv->ResinListItemId000201Allowed = g_LocalConfig.ResinListItemId000201Allowed;
        g_pEnv->ResinListItemId107009Allowed = g_LocalConfig.ResinListItemId107009Allowed;
        g_pEnv->ResinListItemId107012Allowed = g_LocalConfig.ResinListItemId107012Allowed;
        g_pEnv->ResinListItemId220007Allowed = g_LocalConfig.ResinListItemId220007Allowed;
    }
}

std::wstring GetNvHelperPath() {
    wchar_t modulePath[MAX_PATH];
    if (GetModuleFileNameW(nullptr, modulePath, MAX_PATH) == 0) return L"";
    std::wstring moduleDir = modulePath;
    size_t lastSlash = moduleDir.find_last_of(L"\\/");
    if (lastSlash == std::wstring::npos) return L"";
    return moduleDir.substr(0, lastSlash) + L"\\nvhelper.dll";
}

bool InjectDll(HANDLE hProcess, const std::wstring& dllPath) {
    if (GetFileAttributesW(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) return false;

    size_t size = (dllPath.length() + 1) * sizeof(wchar_t);
    LPVOID remoteMem = VirtualAllocEx(hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) return false;
    
    if (!WriteProcessMemory(hProcess, remoteMem, dllPath.c_str(), size, nullptr)) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }
    
    LPTHREAD_START_ROUTINE loadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, loadLibrary, remoteMem, 0, nullptr);
    if (!hThread) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }
    
    WaitForSingleObject(hThread, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    
    return exitCode != 0;
}

extern "C" {
    
    LAUNCHER_API void UpdateConfig(const wchar_t* gamePath, int hideQuest, int disableDamage, int useTouch,
        int disableEventCam, int removeTeamProgress, int redirectCombine, 
        int resin1, int resin2, int resin3, int resin4, int resin5) 
    {
        g_LocalConfig.HideQuestBanner = hideQuest;
        g_LocalConfig.DisableShowDamageText = disableDamage;
        g_LocalConfig.UsingTouchScreen = useTouch;
        g_LocalConfig.DisableEventCameraMove = disableEventCam;
        g_LocalConfig.RemoveOpenTeamProgress = removeTeamProgress;
        g_LocalConfig.RedirectCombineEntry = redirectCombine;
        g_LocalConfig.ResinListItemId000106Allowed = resin1;
        g_LocalConfig.ResinListItemId000201Allowed = resin2;
        g_LocalConfig.ResinListItemId107009Allowed = resin3;
        g_LocalConfig.ResinListItemId107012Allowed = resin4;
        g_LocalConfig.ResinListItemId220007Allowed = resin5;

        SyncSharedMemory();
    }

    LAUNCHER_API int LaunchGameAndInject(const wchar_t* gamePath, const wchar_t* dllPath, const wchar_t* commandLineArgs, wchar_t* errorMessage, int errorMessageSize) {
        WriteLog("=== 启动会话开始 ===");
        HideConsole();
        
        CleanupOldSessions();
        
        SyncSharedMemory();

        if (!ValidateGamePath(gamePath)) {
            if (errorMessage) wcsncpy_s(errorMessage, errorMessageSize, L"游戏路径无效", _TRUNCATE);
            WriteLog("错误: 游戏路径无效");
            return 1;
        }

        std::wstring wGamePath = gamePath;
        std::wstring workingDir = wGamePath.substr(0, wGamePath.find_last_of(L"\\/"));
        
        std::wstring cmdArgs = commandLineArgs ? commandLineArgs : L"";
        wchar_t* pCmdLine = nullptr;
        if (!cmdArgs.empty()) {
            pCmdLine = new wchar_t[cmdArgs.size() + 1];
            wcscpy_s(pCmdLine, cmdArgs.size() + 1, cmdArgs.c_str());
        }

        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = {};
        
        if (!CreateProcessW(gamePath, pCmdLine, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, workingDir.c_str(), &si, &pi)) {
            if (errorMessage) wcsncpy_s(errorMessage, errorMessageSize, L"创建进程失败", _TRUNCATE);
            WriteLog("错误: CreateProcessW 失败 " + std::to_string(GetLastError()));
            if (pCmdLine) delete[] pCmdLine;
            return 3;
        }

        bool injectionSuccess = true;

        std::wstring nvPath = GetNvHelperPath();
        if (!nvPath.empty() && PathFileExistsW(nvPath.c_str())) {
            WriteLog("注入 NvHelper...");
            if (!InjectDll(pi.hProcess, nvPath)) {
                WriteLog("警告: NvHelper 注入失败");
            }
        }

        // 4. [核心] 安全处理与注入主DLL
        if (dllPath && wcslen(dllPath) > 0) {
            WriteLog("准备安全DLL副本...");
            
            std::wstring safeDllPath = PrepareSafeDll(dllPath);

            if (safeDllPath.empty()) {
                WriteLog("致命错误: DLL安全处理失败");
                injectionSuccess = false;
                if (errorMessage) wcsncpy_s(errorMessage, errorMessageSize, L"DLL处理失败", _TRUNCATE);
            } else {
                WriteLog("注入安全副本: " + std::string(safeDllPath.begin(), safeDllPath.end())); // 日志仅调试用
                if (!InjectDll(pi.hProcess, safeDllPath)) {
                    WriteLog("错误: DLL注入失败");
                    injectionSuccess = false;
                    if (errorMessage) wcsncpy_s(errorMessage, errorMessageSize, L"DLL注入失败", _TRUNCATE);
                } else {
                    WriteLog("DLL注入成功");
                }
            }
        }
        
        if (!injectionSuccess) {
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            if (pCmdLine) delete[] pCmdLine;
            return 4;
        }
        
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        if (pCmdLine) delete[] pCmdLine;
        
        WriteLog("=== 启动会话完成 ===");
        return 0;
    }

    LAUNCHER_API int GetDefaultDllPath(wchar_t* dllPath, int dllPathSize) {
        wchar_t modulePath[MAX_PATH];
        GetModuleFileNameW(nullptr, modulePath, MAX_PATH);
        std::wstring path = modulePath;
        path = path.substr(0, path.find_last_of(L"\\/")) + L"\\Genshin.UnlockerIsland.API.dll";
        if (dllPath) wcsncpy_s(dllPath, dllPathSize, path.c_str(), _TRUNCATE);
        return 0;
    }

    LAUNCHER_API bool ValidateGamePath(const wchar_t* gamePath) {
        return gamePath && PathFileExistsW(gamePath);
    }

    LAUNCHER_API bool ValidateDllPath(const wchar_t* dllPath) {
        return dllPath && PathFileExistsW(dllPath);
    }
}