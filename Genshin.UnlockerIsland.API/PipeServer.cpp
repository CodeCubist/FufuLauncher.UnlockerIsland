#include "pch.h"
#include "PipeServer.h"
#include "GameState.h" 
#include <thread>
#include <atomic>
#include <string>
#include <chrono>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>

class Logger {
    std::ofstream logFile;
    std::mutex logMutex;
    std::string logFilePath;

public:
    Logger() {
        char tempPath[MAX_PATH];
        GetTempPathA(MAX_PATH, tempPath);
        logFilePath = std::string(tempPath) + "LauncherProUDP.log";
        logFile.open(logFilePath, std::ios::out | std::ios::app);
        if (logFile.is_open()) {
            Write("=== UDP Server Started ===");
        }
    }

    ~Logger() {
        if (logFile.is_open()) {
            Write("=== UDP Server Stopped ===");
            logFile.close();
        }
    }

    void Write(const std::string& message) {
        std::lock_guard<std::mutex> lock(logMutex);
        if (logFile.is_open()) {
            auto now = std::chrono::system_clock::now();
            auto time = std::chrono::system_clock::to_time_t(now);
            struct tm timeinfo;
            localtime_s(&timeinfo, &time);
            
            logFile << "[" << std::put_time(&timeinfo, "%Y-%m-%d %H:%M:%S") << "] " 
                    << message << "\n";
            logFile.flush();
        }
    }
    std::string GetLogPath() const { return logFilePath; }
};

Logger g_logger;

class UDPServer {
    SOCKET server_socket;
    std::thread server_thread;
    std::atomic<bool> running;
    int port;

public:
    UDPServer(int port = 12345) : running(false), server_socket(INVALID_SOCKET), port(port) {
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
    }

    ~UDPServer() {
        Stop();
        WSACleanup();
    }

    void Start() {
        if (running) return;
        running = true;
        server_thread = std::thread(&UDPServer::Run, this);
        g_logger.Write("UDP服务器线程已启动");
    }

    void Stop() {
        running = false;
        if (server_socket != INVALID_SOCKET) {
            closesocket(server_socket);
            server_socket = INVALID_SOCKET;
        }
        if (server_thread.joinable()) {
            server_thread.join();
        }
    }

    void Run() {
        server_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (server_socket == INVALID_SOCKET) {
            g_logger.Write("Socket创建失败");
            return;
        }

        sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(port);

        if (bind(server_socket, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
            g_logger.Write("端口绑定失败 (Port: 12345)");
            closesocket(server_socket);
            return;
        }

        g_logger.Write("监听端口 12345...");

        char buffer[1024];
        sockaddr_in client_addr;
        int client_len = sizeof(client_addr);

        while (running) {
            int len = recvfrom(server_socket, buffer, sizeof(buffer) - 1, 0, (sockaddr*)&client_addr, &client_len);
            
            if (len > 0) {
                buffer[len] = '\0';
                std::string command(buffer);
                
                command.erase(std::remove(command.begin(), command.end(), '\n'), command.end());
                command.erase(std::remove(command.begin(), command.end(), '\r'), command.end());
                
                bool success = ProcessPipeCommand(command);
                
                std::string response = "OK";
                
                if (command == "heartbeat") {
                    response = "alive";
                } else if (!success) {
                    response = "ERROR";
                }

                sendto(server_socket, response.c_str(), (int)response.length(), 0, (sockaddr*)&client_addr, client_len);
            }
        }
    }
};

UDPServer g_udpServer;
extern "C" {
    __declspec(dllexport) void StartPipeServer() {
        g_udpServer.Start();
    }
    
    __declspec(dllexport) void StopPipeServer() {
        g_udpServer.Stop();
    }
    
    __declspec(dllexport) bool IsClientConnected() {
        return true; 
    }
    
    __declspec(dllexport) bool ProcessPipeCommand(const std::string& command) {
        if (command == "heartbeat") {
            return true;
        }

        std::stringstream ss;
        ss << "收到命令: " << command;
        g_logger.Write(ss.str());
        
        try {
            if (command == "enable_fps_override") {
                menu.enable_fps_override = true;
                return true;
            }
            if (command == "disable_fps_override") {
                menu.enable_fps_override = false;
                return true;
            }
            if (command == "enable_fov_override") {
                menu.enable_fov_override = true;
                return true;
            }
            if (command == "disable_fov_override") {
                menu.enable_fov_override = false;
                return true;
            }
            if (command == "enable_Perspective_override") {
                menu.enable_Perspective_override = true;
                return true;
            }
            if (command == "disable_Perspective_override") {
                menu.enable_Perspective_override = false;
                return true;
            }
            if (command == "enable_display_fog_override") {
                menu.enable_display_fog_override = true;
                return true;
            }
            if (command == "disable_display_fog_override") {
                menu.enable_display_fog_override = false;
                return true;
            }
            
            if (command.find("set_fov ") == 0) {
                std::string val = command.substr(8);
                menu.fov_value = std::stof(val);
                return true;
            }
            if (command.find("set_smoothing ") == 0) {
                std::string val = command.substr(14);
                menu.fov_smoothing_factor = std::stof(val);
                return true;
            }
            if (command.find("set_fps ") == 0) {
                std::string val = command.substr(8);
                menu.selected_fps = std::stoi(val);
                return true;
            }

            return true;
        }
        catch (...) {
            g_logger.Write("命令处理异常");
            return false;
        }
    }
    
    __declspec(dllexport) const char* GetLogFilePath() {
        static std::string path;
        path = g_logger.GetLogPath();
        return path.c_str();
    }
}