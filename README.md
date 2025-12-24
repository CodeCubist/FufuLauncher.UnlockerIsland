# Genshin.Fps.UnlockerIsland

> 📖 [点击查看中文版使用说明](./README_CN.md)

**Unlock your freedom in Teyvat.**  
A lightweight, C++17-based tool for unlocking Genshin Impact's frame rate limit, customizing the in-game field of view (FOV), and disabling fog effects for enhanced clarity.

## ✨ Features

- 🚀 Unlock frame rate up to 2147483647 FPS
- 🎥 Customize in-game Field of View (FOV)
- 🌫️ Remove fog effects to improve visual clarity
- 🧩 DLL injection using `LoadLibraryW`
- 🔧 Realtime memory patching and MinHook detours
- 🖼️ ImGui-based in-game overlay

## 🛠️ Technical Details

- **Language:** C++
- **Standard:** ISO C++17 (`/std:c++17`)
- **Architecture:** 64-bit (x86_64)
- **Platform:** Windows 10/11
- **Injection Method:** LoadLibrary + CreateRemoteThread
- **Hooking Library:** MinHook
- **Graphics API:** DirectX 11

## 🚀 How It Works

The launcher starts Genshin Impact in suspended mode, injects `Genshin.Fps.UnlockerIsland.dll` via `LoadLibraryW`, and resumes the process. The DLL modifies memory to:

- Unlock FPS limit
- Modify camera FOV
- Remove fog-related rendering flags

## 📦 Usage

1. Download the injector and DLL.
2. Ensure `GenshinImpact.exe` or `YuanShen.exe` is available.
3. Run the launcher:
   - Game path will be read from an `.ini` file or selected manually.
   - The launcher starts the game suspended.
   - Injects the DLL using LoadLibrary.
   - Resumes the game.
4. Use `Home` key to toggle the in-game overlay.

## ⚙️ Configuration

- Game path is saved to a `.ini` file after first selection.
- DLL must be in the same folder as the launcher executable.

## 📜 License

This project is licensed under the [MIT License](./LICENSE).  
You are free to use, modify, and distribute it with proper attribution.

## ⚠️ Disclaimer

This is an unofficial third-party tool.  
Using it may violate the Terms of Service of Genshin Impact and result in bans.  
The author assumes **no responsibility** for any consequences resulting from use of this software.

## 📩 Contact

Open an [issue](https://github.com/isxlan0/Genshin.Fps.UnlockerIsland/issues) for bugs, suggestions, or contributions.

---

*For research and educational purposes only.*
