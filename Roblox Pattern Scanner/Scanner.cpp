#include <Windows.h>
#include <filesystem>
#include <tlhelp32.h> 
#include "Scanner.h"

std::pair<std::vector<char>, std::string> hexStringToPattern(const std::string& hexPattern) {
    std::vector<char> bytes;
    std::string mask;
    std::istringstream stream(hexPattern);
    std::string byteString;

    while (stream >> byteString) {
        if (byteString == "?") {
            bytes.push_back(0x00);  // Wildcard byte
            mask += '?';            // Wildcard mask
        }
        else {
            bytes.push_back(static_cast<char>(strtol(byteString.c_str(), nullptr, 16)));
            mask += 'x';            // Exact match mask
        }
    }
    return { bytes, mask };
}

uintptr_t findPattern(const std::string& hexPattern) {
    // Convert hex pattern to bytes and mask
    auto [patternBytes, mask] = hexStringToPattern(hexPattern);

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    uintptr_t minAddress = reinterpret_cast<uintptr_t>(sysInfo.lpMinimumApplicationAddress);
    uintptr_t maxAddress = reinterpret_cast<uintptr_t>(sysInfo.lpMaximumApplicationAddress);

    MEMORY_BASIC_INFORMATION memInfo;
    std::vector<char> buffer;

    for (uintptr_t address = minAddress; address < maxAddress;) {
        if (VirtualQueryEx(Driver->RobloxProcess, reinterpret_cast<LPCVOID>(address), &memInfo, sizeof(memInfo))) {
            // Check if memory is readable/executable
            if (memInfo.State == MEM_COMMIT &&
                (memInfo.Protect == PAGE_EXECUTE_READ ||
                    memInfo.Protect == PAGE_EXECUTE_READWRITE ||
                    memInfo.Protect == PAGE_READONLY)) {

                size_t regionSize = memInfo.RegionSize;
                buffer.resize(regionSize);
                SIZE_T bytesRead = 0;

                Driver->ReadMemory(reinterpret_cast<LPCVOID>(address), buffer.data(), regionSize, &bytesRead);

                for (size_t i = 0; i <= bytesRead - patternBytes.size(); ++i) {
                    bool found = true;
                    for (size_t j = 0; j < patternBytes.size(); ++j) {
                        if (mask[j] == 'x' && buffer[i + j] != patternBytes[j]) {
                            found = false;
                            break;
                        }
                    }
                    if (found) {
                        return address + i;
                    }
                }
            }
            address += memInfo.RegionSize;
        }
        else {
            break;
        }
    }
    return 0;  // Pattern not found
}