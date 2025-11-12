#include <iostream>


     // <-- Added for modern random number generation
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <winsvc.h>
#include <conio.h>
#include <io.h>
#include <fcntl.h>

#include "hwidchecks.h"
#include "ProcessMemory.h" 
#include "offsets.hpp"
#include "triggerbot.h"


HANDLE hijackedHandle;

char getKeyPressed(){
    char kPressed = _getch();
    return kPressed;
}

int delayMs =0;
int toggleKey = VK_XBUTTON2;

int wmain() {
    processes process;
    patternScanning pc;
    tb tb;
    bool running = true;
    bool isCheckingAC = true;
    const wchar_t* antiCheats[] = {L"faceit",L"vgk",L"gcsecure"};
    if (!process.EnableSeDebugPrivilege()) { std::wcout << L"Abra o processo como administradorn"; /* ... */ }
    if (isCheckingAC){
        std::wcout << L"Checking ANTI CHEATS\n";
        for (const wchar_t* serviceName : antiCheats) {
            if (process.IsServiceRunning(serviceName)) {
                std::wcerr << L"ANTI CHEAT ENCONTRADO: " << serviceName << std::endl;
                system("pause");
                exit(0);
            }
            else
            {
                std::wcout << serviceName << L" não encontrado\n";
            }
        }
    }
    findcs find;
    DWORD notepadPid = find.FindNotepadPID();
    if (notepadPid == 0) {
        std::wcerr << L"PROCESS NOT FIND TRY OPENING OR REOPENING IT\n";/*... */
        for (int i = 0; i < 1000; i++) {
            notepadPid = find.FindNotepadPID();
            if (GetAsyncKeyState(VK_DELETE)) {
                return 0;
            }
            std::wcout << L"Tries: " << i << L"/1000\n";
            std::this_thread::sleep_for(std::chrono::seconds(10));
            if (notepadPid) {
                break;
            }
        }
    }

    hijackedHandle = process.HijackRandomHandleToProcess(notepadPid);
    //else {
    //}
    //if hijackedHandle == VALID_HANDLE

    // --- NEW PHASE: Test the Memory Class ---
    std::wcout << L"\n[DEBUG] Phase 6: Testing memory read/write operations..." << std::endl;

    if (hijackedHandle == NULL || 0) {
        std::wcout << L"[INFO] Cannot test memory class because no valid handle was hijacked." << std::endl;
    }
    else {
        try {
            // 1. Instantiate our memory manager with the hijacked handle
            ProcessMemory memory(hijackedHandle);
            std::wcout << L"[TEST] Successfully created ProcessMemory manager for PID " << notepadPid << std::endl;

            // 2. Get the base address of notepad.exe in its own memory
            std::wcout << L"[TEST] Finding base address of cs2.exe..." << std::endl;
            MODULEENTRY32W baseAddress = { 0 };
            while (!baseAddress.modBaseAddr) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                baseAddress = memory.GetModuleEntry(notepadPid, L"client.dll");
            }
            std::wcout << L"[SUCCESS] cs2.exe base address found at: 0x" << std::hex << baseAddress.modBaseAddr << std::dec << std::endl;
            MODULEENTRY32W baseEngine = { 0 };
            while (!baseEngine.modBaseAddr) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                baseEngine = memory.GetModuleEntry(notepadPid, L"engine2.dll");
            }
            std::this_thread::sleep_for(std::chrono::seconds(2));
            std::string dwEntityListPattern = "48 89 35 ?? ?? ?? ?? 48 85 F6";
            std::vector<int> dwEntityListBytes = pc.PatternToBytes(dwEntityListPattern);
            uintptr_t dwEntityListScanned = pc.PatternScan(hijackedHandle, (uintptr_t)baseAddress.modBaseAddr, baseAddress.modBaseSize, dwEntityListBytes);
            uintptr_t dwEntityList = pc.ResolveRipRelativeAddress(hijackedHandle, dwEntityListScanned, 3, 7);
           // uintptr_t dwEntityListOffset = dwEntityList - (uintptr_t)baseAddress.modBaseAddr;
            std::string predictionPattern = "48 8D 05 C3 CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC 40 53 56 41 54";
            std::vector<int> predictionBytes = pc.PatternToBytes(predictionPattern);
            uintptr_t predictionScanned = pc.PatternScan(hijackedHandle, (uintptr_t)baseAddress.modBaseAddr, baseAddress.modBaseSize, predictionBytes);
            uintptr_t predictionAddress = pc.ResolveRipRelativeAddress(hijackedHandle, predictionScanned, 3, 7);


            std::string offsetPattern = "4C 39 B6 74 ?? 44 88 BE";
            std::vector<int> offsetBytes = pc.PatternToBytes(offsetPattern);
            uintptr_t offsetInstruction = pc.PatternScan(hijackedHandle, (uintptr_t)baseAddress.modBaseAddr, baseAddress.modBaseSize, offsetBytes);


            DWORD offsetFromPrediction = memory.Read<DWORD>(offsetInstruction + 3);
            uintptr_t dwLocalPlayerPawn = predictionAddress + offsetFromPrediction;


            _wsystem(L"cls");
            std::wcout << "[PRESS F6] CHANGE DELAY\n";
            int isDelaySetByUser = false;
            while (running) {
                if (GetAsyncKeyState(VK_DELETE)) {
                    running = false;
                    CloseHandle(hijackedHandle);
                }
                if (GetAsyncKeyState(VK_F6)) {
                    delayMs = NULL;
                    std::wcout << "Type the desired delay in ms: \n";
                    std::wcin >> delayMs;
                    std::wcout << "delay changed to MS: \n" << delayMs << std::endl;
                }
                    if (GetAsyncKeyState(toggleKey)) {
                        
                        const auto localPlayerPawn = memory.Read<std::uintptr_t>(dwLocalPlayerPawn);
                        if (!localPlayerPawn) {
                            //std::wcout << L"couldn`t find localplayerpawn\n";
                        }
                        int crossId = memory.Read<int>(localPlayerPawn + offsets::m_iIDEntIndex);

                        if (crossId > 0) {
                            std::cout << "1";
                            const auto entList = memory.Read<std::uintptr_t>(dwEntityList);
                            if (!entList) {
                                std::wcout << L"couldn`t find entlist\n";
                            }
                            std::cout << "2";
                            const auto listEntry = memory.Read<uintptr_t>(entList + 0x8 * (crossId >> 9) + 0x10);
                            if (!listEntry)
                                continue;
                                std::cout << "3";
                            const auto entCtrl = memory.Read<uintptr_t>(listEntry + 112 * (crossId & 0x1FF));
                            if (!entCtrl)
                                continue;
                                std::cout << "4";
                            int entTeam = memory.Read<int>(entCtrl + offsets::m_iTeamNum);
                            int localTeam = memory.Read<int>(localPlayerPawn + offsets::m_iTeamNum);
                            if (entTeam == localTeam)
                                continue;
                                std::cout << "5";
                            int health = memory.Read<int>(entCtrl + offsets::m_iHealth);
                            if (health <= 0 || health > 100)
                                continue;
                                std::cout << "6";
                            tb.simMouse(delayMs);
                            std::cout << "shoot";
                    }
                  
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));

                }

                //}

            }
        }
        catch (const MemoryException& e) {
            std::wcerr << L"[FATAL MEMORY ERROR] " << e.what() << std::endl;
        }
        catch (const std::exception& e) {
            std::wcerr << L"[FATAL GENERIC ERROR] " << e.what() << std::endl;
        }
    }

    std::wcout << L"\nProgram finished. Press any key to exit." << std::endl;
    _wsystem(L"pause");
    return 0;
}