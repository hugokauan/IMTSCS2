#include "triggerbot.h"


void tb::triggerBot(){
    
}


void tb::simMouse(int delayMs) {
    std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
    INPUT input = { 0 };
    input.type = INPUT_MOUSE;
    input.mi.dwFlags = MOUSEEVENTF_LEFTDOWN;
    SendInput(1, &input, sizeof(INPUT));

    ZeroMemory(&input,sizeof(INPUT));

    input.type = INPUT_MOUSE;
    input.mi.dwFlags = MOUSEEVENTF_LEFTUP;
    SendInput(1, &input, sizeof(INPUT));
    
}
