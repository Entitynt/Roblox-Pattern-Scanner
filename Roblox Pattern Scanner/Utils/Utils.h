#pragma once
#include <Windows.h>
#include <string>
#include <TlHelp32.h>
#include <memory>

namespace Utils
{
	inline HWND hwndout;
	uintptr_t rebase(uintptr_t address, uintptr_t moduleBase) {
		return address - moduleBase;
	}
    void SetColor(WORD color) {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hConsole, color);
    }

    void WriteToConsole(const std::string& text) {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD written;
        WriteConsoleA(hConsole, text.c_str(), (DWORD)text.size(), &written, NULL);
        SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);  // Reset to white
    }
}
