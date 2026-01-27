#pragma once
#include <string>

namespace Scanner {
    void* ScanMainMod(const std::string& signature);
    
    void* ResolveRelative(void* instruction, int offset = 1, int instrSize = 5);
}