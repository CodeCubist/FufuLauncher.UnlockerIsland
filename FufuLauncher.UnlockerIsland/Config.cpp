#include "Config.h"
#include <string>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <Windows.h>

ModConfig g_Config;

std::string AnsiToUtf8(const std::string& str) {
    if (str.empty()) return "";
    
    int wLen = MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, nullptr, 0);
    if (wLen <= 0) return str;
    std::vector<wchar_t> wBuf(wLen);
    MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, wBuf.data(), wLen);
    
    int uLen = WideCharToMultiByte(CP_UTF8, 0, wBuf.data(), -1, nullptr, 0, nullptr, nullptr);
    if (uLen <= 0) return str;
    std::vector<char> uBuf(uLen);
    WideCharToMultiByte(CP_UTF8, 0, wBuf.data(), -1, uBuf.data(), uLen, nullptr, nullptr);

    return std::string(uBuf.data());
}

namespace Config {
    ModConfig& Get() { return g_Config; }
    
    int ReadInt(LPCSTR section, int defaultVal, LPCSTR file) {
        return GetPrivateProfileIntA(section, "Value", defaultVal, file);
    }

    float ReadFloat(LPCSTR section, float defaultVal, LPCSTR file) {
        char buf[32];
        char defStr[32];
        snprintf(defStr, sizeof(defStr), "%f", defaultVal);
        GetPrivateProfileStringA(section, "Value", defStr, buf, 32, file);
        return (float)atof(buf);
    }

    void ReadString(LPCSTR section, LPCSTR defaultVal, char* outBuf, int size, LPCSTR file) {
        GetPrivateProfileStringA(section, "Value", defaultVal, outBuf, size, file);
    }
    
    void WriteFloat(LPCSTR section, float value, LPCSTR file) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%.1f", value);
        WritePrivateProfileStringA(section, "Value", buf, file);
    }
    
    std::string GetConfigPath() {
        char path[MAX_PATH];
        HMODULE hm = NULL;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)&g_Config, &hm);
        GetModuleFileNameA(hm, path, sizeof(path));
        
        std::string fullPath = path;
        std::string dirPath;
        size_t lastSlash = fullPath.find_last_of("\\/");
        if (lastSlash != std::string::npos) {
            dirPath = fullPath.substr(0, lastSlash);
        } else {
            dirPath = ".";
        }
        return dirPath + "\\config.ini";
    }
    
    void Load() {
        char path[MAX_PATH];
        HMODULE hm = NULL;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)&g_Config, &hm);
        GetModuleFileNameA(hm, path, sizeof(path));
        
        std::string fullPath = path;
        std::string dirPath;
        
        size_t lastSlash = fullPath.find_last_of("\\/");
        if (lastSlash != std::string::npos) {
            dirPath = fullPath.substr(0, lastSlash);
        } else {
            dirPath = ".";
        }
        
        std::string cfgPath = dirPath + "\\config.ini"; 
        LPCSTR file = cfgPath.c_str();
        
        g_Config.debug_console = ReadInt("DebugConsole", 0, file);
        
        g_Config.enable_fps_override = ReadInt("FpsUnlock", 0, file);
        
        g_Config.selected_fps = ReadInt("TargetFps", 60, file);
        
        g_Config.enable_vsync_override = ReadInt("VSync", 1, file);
        
        g_Config.use_touch_screen = ReadInt("TouchScreen", 0, file);
        
        g_Config.enable_fov_override = ReadInt("FovUnlock", 0, file);
        
        g_Config.fov_value = ReadFloat("FovValue", 45.0f, file);
        
        g_Config.hide_quest_banner = ReadInt("HideQuestBanner", 0, file);
        
        g_Config.hide_uid = ReadInt("HideUID", 0, file);
        
        g_Config.disable_show_damage_text = ReadInt("DisableDamageText", 0, file);
        
        g_Config.disable_event_camera_move = ReadInt("DisableCameraMove", 0, file);
        
        g_Config.disable_fog = ReadInt("DisableFog", 0, file);
        
        g_Config.disable_character_fade = ReadInt("DisableCharFade", 0, file);
        
        g_Config.enable_redirect_craft_override = ReadInt("RedirectCraft", 0, file);
        
        g_Config.enable_remove_team_anim = ReadInt("RemoveTeamAnim", 0, file);
        
        g_Config.toggle_key = ReadInt("ToggleKey", VK_HOME, file);
        
        g_Config.craft_key = ReadInt("CraftKey", 0, file);
        
        g_Config.show_fps_window = ReadInt("ShowFPS", 0, file);
        
        g_Config.enable_custom_title = ReadInt("EnableCustomTitle", 0, file);
        
        char titleBuf[256] = {};
        ReadString("CustomTitleText", "FufuLauncher", titleBuf, sizeof(titleBuf), file);
        g_Config.custom_title_text = titleBuf;

        g_Config.show_cpu_usage = ReadInt("ShowCPU", 1, file);
        
        g_Config.show_gpu_time = ReadInt("ShowGPU", 1, file);
    
        g_Config.show_custom_text = ReadInt("ShowCustomText", 0, file);

        g_Config.show_custom_text = ReadInt("ShowCustomText", 0, file);
        
        char overlayBuf[256] = { 0 };
        ReadString("CustomOverlayText", "FufuLauncher", overlayBuf, sizeof(overlayBuf), file);
        g_Config.custom_overlay_text = std::string(overlayBuf);

        g_Config.overlay_pos_x = ReadFloat("OverlayX", 30.0f, file);
        
        g_Config.overlay_pos_y = ReadFloat("OverlayY", 30.0f, file);

        g_Config.show_time = ReadInt("ShowTime", 0, file);

        g_Config.enable_dx11_hook = ReadInt("EnableDX11Hook", 1, file);

        g_Config.dump_offsets = ReadInt("DumpOffsets", 0, file);
    }
    void SaveOverlayPos(float x, float y) {
        g_Config.overlay_pos_x = x;
        g_Config.overlay_pos_y = y;
        
        std::string cfgPath = GetConfigPath();
        WriteFloat("OverlayX", x, cfgPath.c_str());
        WriteFloat("OverlayY", y, cfgPath.c_str());
    }
}