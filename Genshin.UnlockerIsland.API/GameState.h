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
        m_current += (target - m_current) * m_alpha;
        
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
    bool showGui = false;
    bool show_fps = false;
    bool show_fps_use_floating_window = false;
    int toggleKey = VK_HOME;
    bool waitingForKey = false;
    
    int selected_fps = 60;
    int fps_index = 2;
    
    float fov_value = 90.0f;
    float fov_smoothing_factor = 0.08f;

    bool enable_fps_override = false;
    bool enable_fov_override = false;
    bool enable_display_fog_override = false;
    bool enable_Perspective_override = false;
    bool enable_syncount_override = true;
    
    HWND gameWindow = nullptr;
    bool isFocused = true;       
    bool isCursorVisible = false; 
    bool isAltPressed = false;
    
    ExponentialSmoother fovSmoother{ 0.08f };
};

extern Menu_T menu;