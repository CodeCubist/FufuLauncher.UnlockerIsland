#pragma once
#include <windows.h>
#include <cstdint>

const wchar_t* SHARED_MEM_NAME = L"Global\\{8F4B3C2A-1E0D-9C8B-7A6F-5E4D3C2B1A0F}_Auth";

const char* MASTER_KEY = "8F_r3t5r_S9cr2t_1E0D7m_4D3_0D_1A0F";

#pragma pack(push, 1)
struct AuthPacket {
    uint64_t magic_header;
    uint64_t salt;
    
    DWORD target_pid;
    char process_name[128];
    uint64_t checksum;
};
#pragma pack(pop)

const size_t ENCRYPTED_SIZE = sizeof(AuthPacket) - sizeof(uint64_t) * 2;

class SecurityCrypto {
public:
    static uint64_t CalcChecksum(const AuthPacket* pkt) {
        uint64_t hash = 0xCBF29CE484222325;
        const uint8_t* start = (const uint8_t*)&pkt->target_pid;
        size_t len = sizeof(pkt->target_pid) + sizeof(pkt->process_name);

        for (size_t i = 0; i < len; i++) {
            hash ^= start[i];
            hash *= 0x100000001B3;
            hash = (hash << 5) | (hash >> 59);
        }
        return hash;
    }

    static void ProcessBuffer(uint8_t* buffer, size_t size, uint64_t salt) {
        size_t keyLen = strlen(MASTER_KEY);

        for (size_t i = 0; i < size; i++) {
            uint64_t keyStream = salt + (MASTER_KEY[i % keyLen]) + (i * 1337);
            
            uint8_t dynamicKey = (uint8_t)((keyStream ^ (keyStream >> 8)) & 0xFF);

            buffer[i] ^= dynamicKey;
            
            buffer[i] = ~buffer[i];
        }
    }
};