#pragma once
#include <Windows.h>
#include <string>

struct ModConfig {
    bool debug_console = false;
    
    bool enable_vsync_override = true;
    
    bool enable_fps_override = false;
    
    int selected_fps = 60;
    
    bool enable_fov_override = false;
    
    float fov_value = 45.0f;
    
    bool use_touch_screen = false;
    
    bool hide_quest_banner = false;
    
    bool hide_uid = false;
    
    bool disable_show_damage_text = false;
    
    bool disable_event_camera_move = false;
    
    bool disable_fog = false;
    
    bool disable_character_fade = false;
    
    bool enable_custom_title = false;
    
    std::string custom_title_text = "原神";

    bool enable_redirect_craft_override = false;
    
    bool enable_remove_team_anim = false;

    int toggle_key = VK_HOME;
    
    int craft_key = 0;
    
    bool show_fps_window = false;
    
    bool show_cpu_usage = true;
    
    bool show_gpu_time = true;
    
    bool show_custom_text = false;
    
    std::string custom_overlay_text = "";

    float overlay_pos_x = 30.0f;
    
    float overlay_pos_y = 30.0f;

    bool show_time = false;

    bool enable_dx11_hook = true;

    bool dump_offsets = false;
};

namespace Config {
    ModConfig& Get();
    void Load();
    void SaveOverlayPos(float x, float y);
}