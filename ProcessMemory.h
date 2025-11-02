#pragma once // Prevents the header from being included multiple times

#include <windows.h>
#include <string>
#include <stdexcept>
#include <iostream>  // For debug output
#include <vector>
#include <tlhelp32.h>
#include <stdexcept>
#include <sstream>
#include <cstdint>
#include "nt.h"
#include <random> 

// A custom exception for memory operation failures
class MemoryException : public std::runtime_error {
public:
    MemoryException(const std::string& message) : std::runtime_error(message) {}
};

class ProcessMemory {
public:
    /**
     * @brief Constructs a ProcessMemory manager.
     * @param hProcess A valid handle to the target process with appropriate access rights
     *                 (e.g., PROCESS_VM_READ, PROCESS_VM_WRITE).
     * @note This class does NOT take ownership of the handle. You are responsible
     *       for closing the handle when you are done with it.
     */
    ProcessMemory(HANDLE hProcess);

    /**
     * @brief Gets the base address of a loaded module in the target process.
     * @param moduleName The name of the module (e.g., L"notepad.exe").
     * @return The base address of the module as a uintptr_t.
     * @throws MemoryException if the module cannot be found.
     */
    MODULEENTRY32W GetModuleEntry(DWORD pid, const wchar_t* moduleName);

    /**
     * @brief Reads a value of a specific type from a given memory address.
     * @tparam T The data type to read (e.g., int, float, a struct).
     * @param address The memory address to read from.
     * @return The value read from memory.
     * @throws MemoryException on failure to read.
     */
    template<typename T>
    T Read(uintptr_t address) {
        T buffer; // Create a variable of the specified type
        if (!ReadProcessMemory(m_hProcess, (LPCVOID)address, &buffer, sizeof(T), nullptr)) {
            //throw MemoryException("ReadProcessMemory failed. Error: " + std::to_string(GetLastError()));
        }
        return buffer;
    }

    /**
     * @brief Writes a value of a specific type to a given memory address.
     * @tparam T The data type to write (e.g., int, float, a struct).
     * @param address The memory address to write to.
     * @param value The value to write into memory.
     * @throws MemoryException on failure to write.
     */
    template<typename T>
    void Write(uintptr_t address, T value) {
        if (!WriteProcessMemory(m_hProcess, (LPVOID)address, &value, sizeof(T), NULL)) {
            //throw MemoryException("WriteProcessMemory failed. Error: " + std::to_string(GetLastError()));
        }
    }

    // You could also add non-templated versions for reading/writing raw buffers if needed
    // bool ReadBuffer(uintptr_t address, void* buffer, size_t size);
    // bool WriteBuffer(uintptr_t address, const void* buffer, size_t size);

private:
    HANDLE m_hProcess;
    DWORD m_pid;
};


class findcs{
    public:
    DWORD FindNotepadPID();
    
};

class processes{
    public:
    bool IsServiceRunning(const wchar_t* serviceName);
    bool EnableSeDebugPrivilege();
    HANDLE HijackRandomHandleToProcess(DWORD targetPid);
};

class patternScanning{
    public:

    
    uintptr_t PatternScan(HANDLE processHandle, uintptr_t begin, size_t size, const std::vector<int>& pattern);
    uintptr_t ResolveRipRelativeAddress(HANDLE processHandle, uintptr_t instructionAddress, LONG instructionOffset, LONG instructionSize);
    std::vector<int> PatternToBytes(const std::string& patternString);
};