#include "NTDLL.h"
#include "../Utils/Xor.h"

NtUnlockVirtualMemory_t* NtUnlockVirtualMemory;
NtReadVirtualMemory_t* NtReadVirtualMemory;
NtWriteVirtualMemory_t* NtWriteVirtualMemory;
void NTDLL_INIT_FCNS(HMODULE ntdll) {
    NtUnlockVirtualMemory = (NtUnlockVirtualMemory_t*)GetProcAddress(ntdll, xor_a("NtUnlockVirtualMemory"));
    NtReadVirtualMemory = (NtReadVirtualMemory_t*)GetProcAddress(ntdll, "NtReadVirtualMemory");
    NtWriteVirtualMemory = (NtWriteVirtualMemory_t*)GetProcAddress(ntdll, "NtWriteVirtualMemory");
}