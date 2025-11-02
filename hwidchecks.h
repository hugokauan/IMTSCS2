#pragma once
#include <string>

class hwid {
public:
	std::string getMACAddress();
	std::string getMotherboardSerial();
	std::string getVolumeSerial();

};

tb trigger;
hwid hwidChecker;
HANDLE hijackedHandle;

std::string macAdress = hwidChecker.getMACAddress();
std::string motherboardSerial = hwidChecker.getMotherboardSerial();
std::string diskHwid = hwidChecker.getVolumeSerial();