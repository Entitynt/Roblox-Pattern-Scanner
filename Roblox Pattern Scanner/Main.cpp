#include <Windows.h>
#include <sstream>
#include <queue>
#include <thread>
#include <tlhelp32.h> 
#include <filesystem>
#include "Utils/Xor.h"
#include "Driver/Driver.h"
#include "Utils/utils.h"
#include "Scanner/Scanner.hpp"
#include <psapi.h> 
#pragma comment(lib, "Psapi.lib")

const auto Driver = Memory::get_singleton();

bool findRobloxClients(std::queue<DWORD>& injection_clients) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false; 
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    bool found = false;

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, "RobloxPlayerBeta.exe") == 0) {
                injection_clients.push(pe32.th32ProcessID);
                found = true;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return found;
}

uintptr_t getModuleBaseAddress(DWORD processID, const char* moduleName) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (!hProcess) {
        return 0;
    }

    HMODULE hMods[1024];
    DWORD cbNeeded;
    uintptr_t moduleBaseAddress = 0;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        size_t numModules = cbNeeded / sizeof(HMODULE);
        for (size_t i = 0; i < numModules; i++) {
            char szModName[MAX_PATH];
            if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                if (strstr(szModName, moduleName)) {
                    moduleBaseAddress = reinterpret_cast<uintptr_t>(hMods[i]);
                    break;
                }
            }
        }
    }

    CloseHandle(hProcess);
    return moduleBaseAddress;
}

DWORD pid;
std::queue<DWORD> injection_clients;

int main() {
    SetConsoleTitleA("Entity.dev Pattern Scanner");
    Utils::WriteToConsole("\033[1m" R"(oooooooooooo                 .    o8o      .                         .o8                        
`888'     `8               .o8    `"'    .o8                        "888                        
 888         ooo. .oo.   .o888oo oooo  .o888oo oooo    ooo      .oooo888   .ooooo.  oooo    ooo 
 888oooo8    `888P"Y88b    888   `888    888    `88.  .8'      d88' `888  d88' `88b  `88.  .8'  
 888    "     888   888    888    888    888     `88..8'       888   888  888ooo888   `88..8'   
 888       o  888   888    888 .  888    888 .    `888'    .o. 888   888  888    .o    `888'    
o888ooooood8 o888o o888o   "888" o888o   "888"     .8'     Y8P `Y8bod88P" `Y8bod8P'     `8'     
                                               .o..P'                                           
                                               `Y8P'                                            )" "\n \n");

    Utils::WriteToConsole("\033[1m" R"([Finding Roblox Process & Module Address]
=========================================
)");


    bool clients_found = findRobloxClients(injection_clients);
    if (!clients_found) {
        Utils::WriteToConsole(xor_a("[-] Couldn't find any Roblox Clients to inject into!"));
        return 1;
    }

    pid = injection_clients.front();
    Driver->setup(pid);
    Utils::WriteToConsole("[+] RobloxPlayerBeta PID: \033[36m" + std::to_string(pid) + "\n");

    uintptr_t moduleBase = getModuleBaseAddress(pid, "RobloxPlayerBeta.exe");
    if (moduleBase == 0) {
        Utils::WriteToConsole(xor_a("[-] Failed to get module base address!"));
        return 1;
    }
    Utils::WriteToConsole("[+] RobloxPlayerBeta Module Adress: \033[36m0x" + std::to_string(moduleBase) + "\n\n");
    Driver->init_NTfunctions();
   
    Utils::WriteToConsole("\033[1m" R"([Finding Pattern & Offsets]
===========================
)");

    bool printAddressFound = false;
    bool Luau_executeAddressFound = false;
    bool PushInstanceAddressFound = false;
    bool TaskdeferAddressFound = false;
    bool ScresumeAddressFound = false;
    bool FireproximitypromptAddressFound = false;

    auto startTimer = std::chrono::high_resolution_clock::now();
    while (true) {

        if (!printAddressFound) {
            uintptr_t printAddress = Scanner::findPattern("48 8B C4 48 89 50 10 4C 89 40 18 4C 89 48 20 53 57 48 83 EC 78");
            if (printAddress) {
                std::ostringstream foundAddress;
                foundAddress << "[+] Print found at address: " << std::hex << std::uppercase << "\033[36m0x" << Utils::rebase(printAddress, moduleBase) << "\n";
                Utils::WriteToConsole(foundAddress.str());
                printAddressFound = true;
            }
        }

        if (!Luau_executeAddressFound) {
            uintptr_t Luau_executeAddress = Scanner::findPattern("80 79 06 00 0F 85 ? ? ? ? E9 ? ? ? ?");
            if (Luau_executeAddress) {
                std::ostringstream foundAddress;
                foundAddress << "[+] Luau_execute found at address: " << std::hex << std::uppercase << "\033[36m0x" << Utils::rebase(Luau_executeAddress, moduleBase) << "\n";
                Utils::WriteToConsole(foundAddress.str());
                Luau_executeAddressFound = true;
            }
        }

        if (!PushInstanceAddressFound) {
            uintptr_t PushInstanceAddress = Scanner::findPattern("48 89 5C 24 08 57 48 83 EC ? 48 8B FA 48 8B D9 E8 ? ? ? ? 84 C0 74 ? 48 8B D7 48 8B CB 48 8B 5C 24 30");
            if (PushInstanceAddress) {
                std::ostringstream foundAddress;
                foundAddress << "[+] PushInstance found at address: " << std::hex << std::uppercase << "\033[36m0x" << Utils::rebase(PushInstanceAddress, moduleBase) << "\n";
                Utils::WriteToConsole(foundAddress.str());
                PushInstanceAddressFound = true;
            }
        }

        if (!TaskdeferAddressFound) {
            uintptr_t TaskdeferAddress = Scanner::findPattern("48 8B C4 48 89 58 20 55 56 57 41 56 41 57 48 81 EC ? ? ? ? 48 8B F1");
            if (TaskdeferAddress) {
                std::ostringstream foundAddress;
                foundAddress << "[+] Taskdefer found at address: " << std::hex << std::uppercase << "\033[36m0x" << Utils::rebase(TaskdeferAddress, moduleBase) << "\n";
                Utils::WriteToConsole(foundAddress.str());
                TaskdeferAddressFound = true;
            }
        }

        if (!ScresumeAddressFound) {
            uintptr_t ScresumeAddress = Scanner::findPattern("48 8B C4 44 89 48 20 4C 89 40 18 48 89 50 10 48 89 48 08 53 56 57 41 54 41 55 41 56 41 57 48 81 EC ? ? ? ? 0F 29 70 B8 49 8B F0");
            if (ScresumeAddress) {
                std::ostringstream foundAddress;
                foundAddress << "[+] Scresume found at address: " << std::hex << std::uppercase << "\033[36m0x" << Utils::rebase(ScresumeAddress, moduleBase) << "\n";
                Utils::WriteToConsole(foundAddress.str());
                ScresumeAddressFound = true;
            }
        }

        if (!FireproximitypromptAddressFound) {
            uintptr_t FireproximitypromptAddress = Scanner::findPattern("48 85 C9 0F 84 ? ? ? ? 55 53 56");
            if (FireproximitypromptAddress) {
                std::ostringstream foundAddress;
                foundAddress << "[+] Fireproximityprompt found at address: " << std::hex << std::uppercase << "\033[36m0x" << Utils::rebase(FireproximitypromptAddress, moduleBase) << "\n";
                Utils::WriteToConsole(foundAddress.str());
                FireproximitypromptAddressFound = true;
            }
        }

        if (printAddressFound && Luau_executeAddressFound && PushInstanceAddressFound && TaskdeferAddressFound && ScresumeAddressFound && FireproximitypromptAddressFound) {
            auto endTimer = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double> elapsed = endTimer - startTimer;
            Utils::WriteToConsole("[?] Elapsed time: \033[32m" + std::to_string(elapsed.count()) + "\033[37m seconds\n\n");
            break;
        }

        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    CloseHandle(Driver->RobloxProcess);
    system("pause");
    return 0;
}
