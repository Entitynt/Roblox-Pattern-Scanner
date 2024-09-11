#pragma once

#include <windows.h>
#include <TlHelp32.h>
#include <vector>
#include <iostream>


class Memory {
    static Memory* g_Singleton;
public:
    static Memory* get_singleton() noexcept;

    int process_id;
    HANDLE RobloxProcess;

    bool setup(DWORD proc_id);

    void init_NTfunctions();

    void WriteMemory(LPVOID lpBaseAddress, LPVOID  lpBuffer, SIZE_T  nSize, SIZE_T* lpNumberOfBytesRead);

    void ReadMemory(LPCVOID lpBaseAddress, LPVOID  lpBuffer, SIZE_T  nSize, SIZE_T* lpNumberOfBytesRead);


    template<typename T> void write(uintptr_t address, T value)
    {
        WriteMemory((LPVOID)address, &value, sizeof(T), NULL);
    }
    template<typename T> T read(uintptr_t address)
    {
        T buffer{};
        ReadMemory((LPCVOID)address, &buffer, sizeof(T), NULL);

        return buffer;
    }

    void write_bytes(std::uint64_t address, std::vector<std::uint8_t> bytes) {
        SIZE_T bytesWritten;
        WriteMemory(reinterpret_cast<LPVOID>(address), (LPVOID)bytes.data(), bytes.size(), &bytesWritten);
    }

    auto read_bytes(unsigned long long address, unsigned long size) {
        std::vector<std::uint8_t> buffer(size);
        ReadMemory((LPCVOID)address, buffer.data(), size, NULL);
        return buffer;
    }
};