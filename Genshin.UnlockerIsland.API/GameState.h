#pragma once
#include <windows.h>
#include <algorithm>

class ExponentialSmoother {
public:
    explicit ExponentialSmoother(float smoothingFactor = 0.1f) 
        : m_alpha(smoothingFactor), m_current(0.0f), m_initialized(false) {}

    void SetSmoothing(float alpha) {
        m_alpha = std::clamp(alpha, 0.01f, 1.0f);
    }

    void Reset(float initialValue) {
        m_current = initialValue;
        m_initialized = true;
    }

    float Update(float target) {
        if (!m_initialized) {
            m_current = target;
            m_initialized = true;
            return m_current;
        }
        // 指数移动平均算法
        m_current += (target - m_current) * m_alpha;
        
        // 如果非常接近目标，直接吸附
        if (std::abs(target - m_current) < 0.01f) {
            m_current = target;
        }
        return m_current;
    }

private:
    float m_alpha;
    float m_current;
    bool m_initialized;
};

struct Menu_T
{
    // UI 状态
    bool showGui = false;
    bool show_fps = false;
    bool show_fps_use_floating_window = false;
    int toggleKey = VK_HOME;
    bool waitingForKey = false;

    // FPS 设置
    int selected_fps = 60;
    int fps_index = 2;
    
    // FOV 核心设置
    float fov_value = 90.0f;
    float fov_smoothing_factor = 0.08f; // 平滑系数
    
    // 功能总开关
    bool enable_fps_override = false;
    bool enable_fov_override = false;
    bool enable_display_fog_override = false;
    bool enable_Perspective_override = false;
    bool enable_syncount_override = true;
    
    // 游戏状态检测 (用于智能判断)
    HWND gameWindow = nullptr;
    bool isFocused = true;       
    bool isCursorVisible = false; 
    bool isAltPressed = false;
    
    // 平滑器实例
    ExponentialSmoother fovSmoother{ 0.08f };
};

extern Menu_T menu;