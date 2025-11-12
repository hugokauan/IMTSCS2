#pragma once
#include <string>
#include <iostream>
#include <vector>
#include <sstream>
#include <windows.h>
#include <iphlpapi.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <shlwapi.h>

class hwid {
public:
	std::string getMACAddress(void);
	std::string getMotherboardSerial(void);
	std::string getVolumeSerial(void);

};          
extern std::string macAdress;        
extern std::string motherboardSerial; 
extern std::string diskHwid;      