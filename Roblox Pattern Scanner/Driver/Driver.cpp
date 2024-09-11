#include <string>
#include "Driver.h"
#include "../NtDLL/NTDLL.h"
#include "../Utils/Xor.h"
#include <iostream>
#include <unordered_map>

Memory* Memory::g_Singleton = nullptr;

Memory* Memory::get_singleton() noexcept {
    if (g_Singleton == nullptr)
        g_Singleton = new Memory();
    return g_Singleton;
}

void Memory::init_NTfunctions() {
    HMODULE NTDLL = GetModuleHandleA(xor_a("ntdll.dll"));

    if (!NTDLL)
        return;

    NTDLL_INIT_FCNS(NTDLL);
}

bool Memory::setup(DWORD proc_id) //hard detectable!
{
    this->process_id = proc_id;

    if (!process_id)
        return false;

    this->RobloxProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, this->process_id);

    if (!this->RobloxProcess)
        return false;

    return true;
}

void Memory::WriteMemory(LPVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {
    if (!this->RobloxProcess)
        return;

    MEMORY_BASIC_INFORMATION memInfo;

    static std::unordered_map<LPCVOID, MEMORY_BASIC_INFORMATION> cachedMemoryInfo;
    if (cachedMemoryInfo.find(lpBaseAddress) == cachedMemoryInfo.end()) {
        VirtualQueryEx(this->RobloxProcess, lpBaseAddress, &memInfo, sizeof(memInfo));
        cachedMemoryInfo[lpBaseAddress] = memInfo;
    }
    else {
        memInfo = cachedMemoryInfo[lpBaseAddress];
    }

    if (WriteProcessMemory(this->RobloxProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten)) {
        PVOID baseAddress = memInfo.AllocationBase;
        SIZE_T regionSize = memInfo.RegionSize;
        NtUnlockVirtualMemory(this->RobloxProcess, &baseAddress, &regionSize, 1);
    }
}

void Memory::ReadMemory(LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead) {
    if (!this->RobloxProcess)
        return;

    MEMORY_BASIC_INFORMATION memInfo;

    static std::unordered_map<LPCVOID, MEMORY_BASIC_INFORMATION> cachedMemoryInfo;
    if (cachedMemoryInfo.find(lpBaseAddress) == cachedMemoryInfo.end()) {
        VirtualQueryEx(this->RobloxProcess, lpBaseAddress, &memInfo, sizeof(memInfo));
        cachedMemoryInfo[lpBaseAddress] = memInfo;
    }
    else {
        memInfo = cachedMemoryInfo[lpBaseAddress];
    }

    if (ReadProcessMemory(this->RobloxProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead)) {
        PVOID baseAddress = memInfo.AllocationBase;
        SIZE_T regionSize = memInfo.RegionSize;
        NtUnlockVirtualMemory(this->RobloxProcess, &baseAddress, &regionSize, 1);
    }
}