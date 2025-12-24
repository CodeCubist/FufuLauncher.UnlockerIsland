# Genshin.Fps.UnlockerIsland

**释放你在提瓦特的极限性能。**  
这是一个基于 C++17 的轻量级工具，用于解锁《原神》的帧率限制、调整游戏视角（FOV），以及去除雾效以提升画面清晰度。

## ✨ 功能特性

- 🚀 解锁帧率上限（最高支持至 2147483647 FPS）
- 🎥 自定义视角范围（FOV）
- 🌫️ 去除雾效，提升场景可视性
- 🧩 使用 `LoadLibraryW` 方式注入 DLL
- 🔧 实时内存 Patch 与 MinHook 函数 Hook
- 🖼️ 基于 ImGui 的游戏内界面

## 🛠️ 技术细节

- **语言：** C++
- **标准：** ISO C++17 (`/std:c++17`)
- **架构：** 64 位（x86_64）
- **平台：** Windows 10/11
- **注入方式：** LoadLibrary + CreateRemoteThread
- **Hook 库：** MinHook
- **图形 API：** DirectX 11

## 🚀 工作原理

启动器会以挂起模式启动游戏进程，通过 `LoadLibraryW` 注入 `Genshin.Fps.UnlockerIsland.dll`，注入完成后恢复游戏运行。DLL 在注入后会进行内存修改：

- 解锁帧率限制
- 调整摄像机视角（FOV）
- 去除场景渲染中的雾效标志

## 📦 使用方法

1. 下载启动器和 DLL。
2. 确保存在 `GenshinImpact.exe` 或 `YuanShen.exe`。
3. 运行启动器：
   - 自动读取 `.ini` 文件中的游戏路径，或弹出对话框选择；
   - 以挂起模式启动游戏；
   - 使用 LoadLibrary 注入 DLL；
   - 自动恢复主线程。
4. 游戏中按下 `Home` 键可打开功能界面。

## ⚙️ 配置说明

- 启动器会生成与其同名的 `.ini` 配置文件，用于保存游戏路径；
- DLL 文件需与启动器处于同一目录。

## 📜 开源协议

本项目基于 [MIT 协议](./LICENSE) 开源发布。  
允许自由使用、修改与发布，需保留原始作者署名。

## ⚠️ 使用声明

本工具为非官方第三方插件。  
使用可能违反原神的用户协议，存在封号风险。  
作者不对使用本工具产生的任何后果承担责任。

## 📩 联系反馈

如需反馈 Bug 或提交建议，请在 [Issues 页面](https://github.com/isxlan0/Genshin.Fps.UnlockerIsland/issues) 提出。

---

*本项目仅供学习与研究使用，禁止用于商业用途。*
