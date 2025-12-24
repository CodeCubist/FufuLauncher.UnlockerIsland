#pragma once

#ifdef __cplusplus
extern "C" {
#endif

    __declspec(dllexport) void StartPipeServer();
    __declspec(dllexport) void StopPipeServer();
    __declspec(dllexport) bool ProcessPipeCommand(const std::string& command);
    __declspec(dllexport) bool IsClientConnected();
    __declspec(dllexport) const char* GetLogFilePath();

#ifdef __cplusplus
}
#endif

#pragma comment(lib, "ws2_32.lib")