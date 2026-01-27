#include "Scanner.h"

// 必须先包含 Windows.h，以此引入核心类型定义
#include <Windows.h> 
#include <Psapi.h>

#include <sstream>
#include <vector>
#include <iostream>

#include "Config.h"


namespace Scanner {

    std::vector<int> ParsePattern(const std::string& signature) {
        std::vector<int> pattern;
        std::stringstream ss(signature);
        std::string word;
        while (ss >> word) {
            if (word == "?" || word == "??") pattern.push_back(-1);
            else {
                try { pattern.push_back(std::stoi(word, nullptr, 16)); }
                catch (...) { pattern.push_back(-1); }
            }
        }
        return pattern;
    }
    
    void* ScanMainMod(const std::string& signature) {
        HMODULE hModule = GetModuleHandle(nullptr);
        if (!hModule) return nullptr;

        MODULEINFO modInfo = { 0 };
        if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(MODULEINFO))) {
            return nullptr;
        }

        auto pattern = ParsePattern(signature);
        if (pattern.empty()) return nullptr;

        uintptr_t startAddr = (uintptr_t)modInfo.lpBaseOfDll;
        uintptr_t endAddr = startAddr + modInfo.SizeOfImage;
        uintptr_t current = startAddr;
        
        MEMORY_BASIC_INFORMATION mbi;
        while (current < endAddr) {
            if (VirtualQuery((LPCVOID)current, &mbi, sizeof(mbi)) == 0) {
                break;
            }
            
            bool isGood = (mbi.State == MEM_COMMIT) &&
                          ((mbi.Protect & PAGE_EXECUTE_READ) || 
                           (mbi.Protect & PAGE_EXECUTE_READWRITE) || 
                           (mbi.Protect & PAGE_READONLY) || 
                           (mbi.Protect & PAGE_READWRITE));

            if (isGood) {
                size_t regionSize = mbi.RegionSize;
                if ((uintptr_t)mbi.BaseAddress + regionSize > endAddr) {
                    regionSize = endAddr - (uintptr_t)mbi.BaseAddress;
                }
                
                const uint8_t* pStart = (const uint8_t*)mbi.BaseAddress;
                const size_t pSize = pattern.size();

                for (size_t i = 0; i <= regionSize - pSize; ++i) {
                    bool found = true;
                    for (size_t j = 0; j < pSize; ++j) {
                        if (pattern[j] != -1 && pattern[j] != pStart[i + j]) {
                            found = false;
                            break;
                        }
                    }
                    if (found) {
                        return (void*)(pStart + i);
                    }
                }
            }
            
            current = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        }

        return nullptr;
    }

    void* ResolveRelative(void* instruction, int offset, int instrSize) {
        if (!instruction) return nullptr;
        __try {
            uintptr_t instrAddr = (uintptr_t)instruction;
            int32_t relative = *(int32_t*)(instrAddr + offset);
            uintptr_t target = instrAddr + instrSize + relative;
            return (void*)target;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return nullptr;
        }
    }
}
