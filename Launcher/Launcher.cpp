#include <windows.h>
#include <shlwapi.h>
#include <string>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <vector>
#include "Launcher.h"
#include "SecurityUtils.h" // 确保包含此头文件

#pragma comment(lib, "shlwapi.lib")

const wchar_t* PLUGINS_SUBDIR_NAME = L"Plugins"; 

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
    
    // 等待 LoadLibrary 返回 (DllMain 执行完毕)
    WaitForSingleObject(hThread, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    
    return exitCode != 0;
}

void RecursiveScanAndInject(HANDLE hProcess, const std::wstring& directory, int& injectedCount) {
    std::wstring searchPath = directory + L"\\*";
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0)
            continue;

        std::wstring fullPath = directory + L"\\" + findData.cFileName;

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            RecursiveScanAndInject(hProcess, fullPath, injectedCount);
        } else {
            size_t nameLen = wcslen(findData.cFileName);
            if (nameLen > 4) {
                const wchar_t* ext = findData.cFileName + nameLen - 4;
                if (_wcsicmp(ext, L".dll") == 0) {
                    std::wstring wFileName = findData.cFileName;
                    std::string sFileName(wFileName.begin(), wFileName.end());

                    WriteLog("发现插件: " + sFileName + "，正在注入...");

                    if (InjectDll(hProcess, fullPath)) {
                        WriteLog("插件注入成功: " + sFileName);
                        injectedCount++;
                    } else {
                        WriteLog("错误: 插件注入失败: " + sFileName);
                    }
                }
            }
        }

    } while (FindNextFileW(hFind, &findData) != 0);

    FindClose(hFind);
}

void InjectPlugins(HANDLE hProcess) {
    wchar_t modulePath[MAX_PATH];
    if (GetModuleFileNameW(nullptr, modulePath, MAX_PATH) == 0) return;
    
    std::wstring moduleDir = modulePath;
    size_t lastSlash = moduleDir.find_last_of(L"\\/");
    if (lastSlash == std::wstring::npos) return;
    
    std::wstring pluginsDir = moduleDir.substr(0, lastSlash) + L"\\" + PLUGINS_SUBDIR_NAME;

    if (GetFileAttributesW(pluginsDir.c_str()) == INVALID_FILE_ATTRIBUTES) {
        WriteLog("未找到 Plugins 目录，跳过插件加载。");
        return;
    }

    WriteLog("正在递归扫描插件目录: " + std::string(pluginsDir.begin(), pluginsDir.end()));
    
    int totalInjected = 0;
    RecursiveScanAndInject(hProcess, pluginsDir, totalInjected);

    WriteLog("插件加载完成，共注入: " + std::to_string(totalInjected) + " 个插件");
}

extern "C" {
    
    LAUNCHER_API int LaunchGameAndInject(const wchar_t* gamePath, const wchar_t* dllPath, const wchar_t* commandLineArgs, wchar_t* errorMessage, int errorMessageSize) {
        WriteLog("=== 启动会话开始 ===");
        HideConsole();
        
        if (!ValidateGamePath(gamePath)) {
            if (errorMessage) wcsncpy_s(errorMessage, errorMessageSize, L"游戏路径无效", _TRUNCATE);
            WriteLog("错误: 游戏路径无效");
            return 1;
        }

        std::wstring wGamePath = gamePath;
        std::wstring workingDir = wGamePath.substr(0, wGamePath.find_last_of(L"\\/"));
        std::wstring exeName = wGamePath.substr(wGamePath.find_last_of(L"\\/") + 1);

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
        
        HANDLE hMapFile = NULL; 
        void* pSharedBuf = NULL;

        WriteLog("正在构建校验...");
        hMapFile = CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            NULL,
            PAGE_READWRITE,
            0,
            sizeof(AuthPacket),
            SHARED_MEM_NAME
        );

        if (hMapFile == NULL) {
            WriteLog("无法创建共享内存! 错误码: " + std::to_string(GetLastError()));
        } else {
            pSharedBuf = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(AuthPacket));
            
            if (pSharedBuf == NULL) {
                WriteLog("无法映射内存视图");
                CloseHandle(hMapFile);
                hMapFile = NULL;
            } else {
                AuthPacket packet = {};
                packet.magic_header = 0xDEADBEEFCAFEBABE;
                packet.salt = GetTickCount64() ^ 0x9988776655443322;
                packet.target_pid = pi.dwProcessId;
                
                std::string sName(exeName.begin(), exeName.end());
                strncpy_s(packet.process_name, sName.c_str(), sizeof(packet.process_name) - 1);
                
                packet.checksum = SecurityCrypto::CalcChecksum(&packet);
                
                SecurityCrypto::ProcessBuffer((uint8_t*)&packet.target_pid, ENCRYPTED_SIZE, packet.salt);
                
                CopyMemory(pSharedBuf, &packet, sizeof(AuthPacket));
                

                UnmapViewOfFile(pSharedBuf);
            }
        }

        InjectPlugins(pi.hProcess);
        
        if (hMapFile) {
            WriteLog("正在等待 DLL 读取验证数据...");
            Sleep(2000);
            
            CloseHandle(hMapFile);
            WriteLog("共享内存句柄已关闭");
        }
        
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        if (pCmdLine) delete[] pCmdLine;
        
        WriteLog("=== 启动会话完成 ===");
        return 0;
    }

    LAUNCHER_API int GetDefaultDllPath(wchar_t* dllPath, int dllPathSize) {
        if (dllPath && dllPathSize > 0) {
            dllPath[0] = L'\0';
        }
        return 0;
    }

    LAUNCHER_API bool ValidateGamePath(const wchar_t* gamePath) {
        return gamePath && PathFileExistsW(gamePath);
    }

    LAUNCHER_API bool ValidateDllPath(const wchar_t* dllPath) {
        return dllPath && PathFileExistsW(dllPath);
    }
}