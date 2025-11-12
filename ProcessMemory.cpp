#include "ProcessMemory.h"



ProcessMemory::ProcessMemory(HANDLE hProcess) {
    if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) {
        throw std::invalid_argument("Provided handle is not valid.");
    }
    m_hProcess = hProcess;
    m_pid = GetProcessId(hProcess);
    if (m_pid == 0) {
        throw MemoryException("Could not get PID from handle. The handle might be invalid or closed.");
    }
}


DWORD findcs::FindNotepadPID() {
    std::wcout << L"\n[DEBUG] Phase 2: Finding cs2.exe Process ID..." << std::endl;
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[ERROR] CreateToolhelp32Snapshot failed. Error: " << GetLastError() << std::endl;
        return 0;
    }
    if (Process32FirstW(hProcessSnap, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, L"cs2.exe") == 0) {
                DWORD pid = pe32.th32ProcessID;
                std::wcout << L"[SUCCESS] Found cs2.exe with PID: " << pid << std::endl;
                CloseHandle(hProcessSnap);
                return pid;
            }
        } while (Process32NextW(hProcessSnap, &pe32));
    }
    std::wcerr << L"[ERROR] Could not find cs2.exe process. Please open Notepad." << std::endl;
    CloseHandle(hProcessSnap);
    return 0;
}
/*uintptr_t ProcessMemory::GetModuleBaseAddress(const wchar_t* moduleName) {
    // We need a snapshot of the modules loaded by the target process
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_pid);
    if (hSnap == INVALID_HANDLE_VALUE) {
        throw MemoryException("CreateToolhelp32Snapshot failed. Error: " + std::to_string(GetLastError()));
    }

    MODULEENTRY32W me32;
    me32.dwSize = sizeof(MODULEENTRY32W);

    // Iterate through the modules
    if (Module32FirstW(hSnap, &me32)) {
        do {
            if (_wcsicmp(me32.szModule, moduleName) == 0) {
                // Found it!
                CloseHandle(hSnap);
                return (uintptr_t)me32.modBaseAddr;
            }
        } while (Module32NextW(hSnap, &me32));
    }

    // If we get here, we didn't find the module
    CloseHandle(hSnap);
    throw MemoryException("Module '" + std::string(moduleName, moduleName + wcslen(moduleName)) + "' not found in process.");
}*/
MODULEENTRY32W ProcessMemory::GetModuleEntry(DWORD pid, const wchar_t* moduleName) {
    // Debug output is great for development.
    std::wcout << L"[DEBUG] Getting module entry for PID: " << pid << L", Module: " << moduleName << std::endl;

    if (pid == 0) {
        throw std::invalid_argument("Process ID cannot be zero.");
    }

    // Create a snapshot of the modules loaded by the target process.
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);

    if (hSnap == INVALID_HANDLE_VALUE) {
        DWORD lastError = GetLastError();
        // The custom exception is a great way to handle errors.
        throw MemoryException("CreateToolhelp32Snapshot failed. Error: " + std::to_string(lastError));
    }

    MODULEENTRY32W me32;
    me32.dwSize = sizeof(MODULEENTRY32W); // IMPORTANT: Set the size before first use.

    // Iterate through the modules in the snapshot.
    if (Module32FirstW(hSnap, &me32)) {
        do {
            // Compare the module name (case-insensitive).
            if (_wcsicmp(me32.szModule, moduleName) == 0) {
                // --- KEY CHANGE ---
                // Found the module! Return the entire struct.
                std::wcout << L"[SUCCESS] Found " << moduleName << L" at address: 0x"
                    << std::hex << (uintptr_t)me32.modBaseAddr
                    << L", Size: " << me32.modBaseSize << " bytes" << std::dec << std::endl;

                CloseHandle(hSnap);
                return me32; // Return the whole struct
            }
        } while (Module32NextW(hSnap, &me32));
    }

    // If we get here, the module was not found.
    CloseHandle(hSnap);

    // Using a basic string conversion for the error message.
    std::wstring wModule(moduleName);
    std::string sModule(wModule.begin(), wModule.end());
    throw MemoryException("Module '" + sModule + "' not found in process with PID " + std::to_string(pid) + ".");
}

bool processes::IsServiceRunning(const wchar_t* serviceName) {
    bool isRunning = false;
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    SERVICE_STATUS_PROCESS ssp;
    DWORD dwBytesNeeded;

    // 1. Abrir o Service Control Manager
    hSCManager = OpenSCManager(
        NULL,                    // M�quina local
        NULL,                    // Banco de dados padr�o (SERVICES_ACTIVE_DATABASE)
        SC_MANAGER_CONNECT       // Direito de acesso necess�rio para conectar
    );

    if (hSCManager == NULL) {
        std::cerr << "Erro ao abrir o SCM: " << GetLastError() << std::endl;
        return false;
    }

    // 2. Abrir o servi�o desejado
    hService = OpenServiceW(
        hSCManager,              // Handle do SCM
        serviceName,             // Nome do servi�o (nome curto, n�o o de exibi��o)
        SERVICE_QUERY_STATUS     // Direito de acesso para consultar o status
    );

    if (hService == NULL) {
        std::wcerr << L"Erro ao abrir o servico '" << serviceName << "': " << GetLastError() << std::endl;
        // O erro 1060 (ERROR_SERVICE_DOES_NOT_EXIST) � comum se o nome estiver errado.
        CloseServiceHandle(hSCManager);
        return false;
    }

    // 3. Consultar o status do servi�o
    if (!QueryServiceStatusEx(
        hService,
        SC_STATUS_PROCESS_INFO, // N�vel de informa��o a ser consultado
        (LPBYTE)&ssp,           // Ponteiro para a estrutura que receber� a informa��o
        sizeof(SERVICE_STATUS_PROCESS),
        &dwBytesNeeded))
    {
        std::cerr << "Erro ao consultar o status do servico: " << GetLastError() << std::endl;
    }
    else {
        // 4. Verificar o estado do servi�o
        if (ssp.dwCurrentState == SERVICE_RUNNING) {
            isRunning = true;
        }
    }

    // 5. Limpeza: Fechar os handles
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    return isRunning;
}


// Converts a string pattern (e.g., "48 8B ? ?") into a byte vector.
std::vector<int> patternScanning::PatternToBytes(const std::string& patternString) {
    std::vector<int> bytes;
    std::stringstream ss(patternString);
    std::string byteStr;

    while (ss >> byteStr) {
        if (byteStr == "?" || byteStr == "??") {
            bytes.push_back(-1); // -1 represents a wildcard.
        }
        else {
            bytes.push_back(std::stoi(byteStr, nullptr, 16));
        }
    }
    return bytes;
}

// Scans a memory region for the specified byte pattern.
uintptr_t patternScanning::PatternScan(HANDLE processHandle, uintptr_t begin, size_t size, const std::vector<int>& pattern) {
    std::vector<byte> buffer(size);
    SIZE_T bytesRead;

    if (!ReadProcessMemory(processHandle, (LPCVOID)begin, buffer.data(), size, &bytesRead)) {
        std::cerr << "Failed to read process memory. Error: " << GetLastError() << std::endl;
        return 0;
    }

    buffer.resize(bytesRead);
    const size_t patternSize = pattern.size();

    for (uintptr_t i = 0; i <= buffer.size() - patternSize; ++i) {
        bool found = true;
        for (size_t j = 0; j < patternSize; ++j) {
            if (pattern[j] != -1 && pattern[j] != buffer[i + j]) {
                found = false;
                break;
            }
        }
        if (found) {
            return begin + i;
        }
    }
    return 0;
}

// Calculates the final address from a RIP-relative instruction.
uintptr_t patternScanning::ResolveRipRelativeAddress(HANDLE processHandle, uintptr_t instructionAddress, LONG instructionOffset, LONG instructionSize) {
    if (!instructionAddress) {
        return 0;
    }

    DWORD relativeOffset = 0;
    if (!ReadProcessMemory(processHandle, (LPCVOID)(instructionAddress + instructionOffset), &relativeOffset, sizeof(DWORD), nullptr)) {
        std::cerr << "Failed to read relative offset. Error: " << GetLastError() << std::endl;
        return 0;
    }

    // The final address is the address of the NEXT instruction, plus the relative offset.
    return instructionAddress + instructionSize + relativeOffset;
}

bool processes::EnableSeDebugPrivilege() {
    std::wcout << L"[DEBUG] Phase 1: Enabling SeDebugPrivilege..." << std::endl;
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::wcerr << L"[ERROR] Could not open process token. Error: " << GetLastError() << std::endl;
        return false;
    }
    TOKEN_PRIVILEGES tkp;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid)) {
        std::wcerr << L"[ERROR] LookupPrivilegeValue failed. Error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, NULL)) {
        std::wcerr << L"[ERROR] AdjustTokenPrivileges failed. Error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        std::wcerr << L"[ERROR] The token does not have the specified privilege. Are you running as Administrator?" << std::endl;
        CloseHandle(hToken);
        return false;
    }
    std::wcout << L"[SUCCESS] SeDebugPrivilege enabled." << std::endl;
    CloseHandle(hToken);
    return true;
}



/**
 * @brief Finds handles to a target process and returns ONE randomly chosen handle.
 *
 * @param targetPid The Process ID of the target (e.g., notepad.exe).
 * @return A single duplicated handle with PROCESS_ALL_ACCESS, or NULL on failure.
 */
HANDLE processes::HijackRandomHandleToProcess(DWORD targetPid) {
    std::wcout << L"\n[DEBUG] Phase 3: Starting Handle Hijacking Process for PID " << targetPid << L"..." << std::endl;
    std::vector<HANDLE> foundHandles; // Temporarily store all found handles

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    pfnNtQuerySystemInformation NtQuerySystemInformation = (pfnNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) {
        std::wcerr << L"[ERROR] Could not get address of NtQuerySystemInformation." << std::endl;
        return NULL;
    }

    // (Code to query system handles is unchanged)
    PSYSTEM_HANDLE_INFORMATION pHandleInfo = nullptr;
    ULONG bufferSize = 1024;
    NTSTATUS status;
    do {
        pHandleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(pHandleInfo, bufferSize);
        if (!pHandleInfo) { std::wcerr << L"[ERROR] Memory allocation failed." << std::endl; return NULL; }
        status = NtQuerySystemInformation(16, pHandleInfo, bufferSize, &bufferSize);
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (status != STATUS_SUCCESS) {
        std::wcerr << L"[ERROR] NtQuerySystemInformation failed with status: " << std::hex << status << std::endl;
        free(pHandleInfo);
        return NULL;
    }
    std::wcout << L"[DEBUG] Found " << pHandleInfo->NumberOfHandles << L" handles system-wide." << std::endl;

    // Iterate and find all matches
    for (ULONG i = 0; i < pHandleInfo->NumberOfHandles; ++i) {
        // (The filtering logic is the same)
        auto handleEntry = pHandleInfo->Handles[i];
        if (handleEntry.UniqueProcessId == GetCurrentProcessId() || handleEntry.UniqueProcessId == 4) continue;
        HANDLE hOwnerProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handleEntry.UniqueProcessId);
        if (!hOwnerProc) continue;
        HANDLE hTempDup = nullptr;
        if (!DuplicateHandle(hOwnerProc, (HANDLE)handleEntry.HandleValue, GetCurrentProcess(), &hTempDup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            CloseHandle(hOwnerProc);
            continue;
        }
        DWORD handleTargetPid = GetProcessId(hTempDup);

        if (handleTargetPid == targetPid) {
            std::wcout << L"[MATCH FOUND] Handle 0x" << std::hex << handleEntry.HandleValue
                << L" in owner PID " << std::dec << handleEntry.UniqueProcessId
                << L" points to our target Notepad PID " << targetPid << L"!" << std::endl;

            HANDLE hHijacked = nullptr;
            if (DuplicateHandle(hOwnerProc, (HANDLE)handleEntry.HandleValue, GetCurrentProcess(), &hHijacked, PROCESS_ALL_ACCESS, FALSE, 0)) {
                std::wcout << L"[SUCCESS]   -> Hijacked handle. New handle in our process: 0x" << std::hex << hHijacked << std::dec << std::endl;
                foundHandles.push_back(hHijacked); // Add to our temporary vector
            }
            else {
                std::wcerr << L"[ERROR]     -> Failed to hijack handle. Error: " << GetLastError() << std::endl;
            }
        }
        CloseHandle(hTempDup);
        CloseHandle(hOwnerProc);
    }
    free(pHandleInfo);

    // --- NEW LOGIC: RANDOMLY SELECT ONE HANDLE ---
    std::wcout << L"\n[DEBUG] Phase 4: Hijacking complete. Found " << foundHandles.size() << L" total handles." << std::endl;

    if (foundHandles.empty()) {
        std::wcout << L"[INFO] No hijackable handles were found." << std::endl;
        return NULL; // Return NULL to indicate no handle was found/returned
    }

    // Setup modern C++ random number generator
    std::random_device rd;  // Obtain a random number from hardware
    std::mt19937 gen(rd()); // Seed the generator
    std::uniform_int_distribution<> distrib(0, foundHandles.size() - 1); // Define the range

    // Pick a random index
    int randomIndex = distrib(gen);
    HANDLE chosenHandle = foundHandles[randomIndex];

    std::wcout << L"[ACTION] Randomly selected handle at index " << randomIndex
        << L" (Value: 0x" << std::hex << chosenHandle << L")." << std::dec << std::endl;
    std::wcout << L"[ACTION] Closing all other " << foundHandles.size() - 1 << L" unused handles to prevent leaks." << std::endl;

    // IMPORTANT: Clean up all handles we duplicated but are NOT returning
    for (size_t i = 0; i < foundHandles.size(); ++i) {
        if (i != randomIndex) {
            CloseHandle(foundHandles[i]);
        }
    }

    return chosenHandle; // Return only the single, randomly selected handle
}