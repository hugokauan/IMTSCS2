#include <iostream>
#include <string>
#include <vector>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#include <iphlpapi.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <shlwapi.h>
#include "hwidchecks.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "shlwapi.lib")

std::string hwid::getMACAddress() {
    std::string macAddress = "N/A";
    ULONG bufferSize = sizeof(IP_ADAPTER_INFO);
    std::vector<IP_ADAPTER_INFO> adapterInfo(1);

    if (GetAdaptersInfo(adapterInfo.data(), &bufferSize) == ERROR_BUFFER_OVERFLOW) {
        adapterInfo.resize(bufferSize / sizeof(IP_ADAPTER_INFO));
        if (GetAdaptersInfo(adapterInfo.data(), &bufferSize) != NO_ERROR) {
            return macAddress;
        }
    }

    if (!adapterInfo.empty()) {
        char macStr[18];
        snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
            adapterInfo[0].Address[0], adapterInfo[0].Address[1],
            adapterInfo[0].Address[2], adapterInfo[0].Address[3],
            adapterInfo[0].Address[4], adapterInfo[0].Address[5]);
        macAddress = macStr;
    }
    return macAddress;
}

std::string hwid::getMotherboardSerial() {
    std::string serialNumber = "N/A";
    HRESULT hres;

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) return serialNumber;

    hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hres)) {
        CoUninitialize();
        return serialNumber;
    }

    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) {
        CoUninitialize();
        return serialNumber;
    }

    IWbemServices* pSvc = NULL;
    hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hres)) {
        pLoc->Release();
        CoUninitialize();
        return serialNumber;
    }

    hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return serialNumber;
    }

    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(bstr_t("WQL"), bstr_t("SELECT SerialNumber FROM Win32_BaseBoard"), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return serialNumber;
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    while (pEnumerator) {
        pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) break;

        VARIANT vtProp;
        pclsObj->Get(L"SerialNumber", 0, &vtProp, 0, 0);
        if (vtProp.vt == VT_BSTR) {
            _bstr_t bstr(vtProp.bstrVal, false);
            serialNumber = std::string(bstr);
        }
        VariantClear(&vtProp);
        pclsObj->Release();
    }

    pSvc->Release();
    pLoc->Release();
    pEnumerator->Release();
    CoUninitialize();

    return serialNumber;
}

std::string hwid::getVolumeSerial() {
    std::string volumeSerial = "N/A";
    DWORD serialNum = 0;
    if (GetVolumeInformationA("C:\\", NULL, 0, &serialNum, NULL, NULL, NULL, 0)) {
        std::stringstream ss;
        ss << std::hex << serialNum;
        volumeSerial = ss.str();
    }
    return volumeSerial;
}

#elif __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <sys/param.h>
#include <sys/mount.h>
#include "hwidchecks.h"

std::string hwid::getMACAddress() {
    io_iterator_t intfIterator;
    if (KERN_SUCCESS != FindEthernetInterfaces(&intfIterator)) return "N/A";

    io_object_t intfService;
    std::string macAddress = "N/A";
    while ((intfService = IOIteratorNext(intfIterator))) {
        CFDataRef macAddressData = (CFDataRef)IORegistryEntryCreateCFProperty(intfService, CFSTR(kIOMACAddress), kCFAllocatorDefault, 0);
        if (macAddressData) {
            const UInt8* data = CFDataGetBytePtr(macAddressData);
            char macStr[18];
            snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x", data[0], data[1], data[2], data[3], data[4], data[5]);
            macAddress = macStr;
            CFRelease(macAddressData);
        }
        IOObjectRelease(intfService);
        if (macAddress != "N/A") break; // Found first one
    }
    IOObjectRelease(intfIterator);
    return macAddress;
}

std::string hwid::getMotherboardSerial() {
    std::string serial = "N/A";
    io_service_t platformExpert = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
    if (platformExpert) {
        CFTypeRef serialNumberAsCFString = IORegistryEntryCreateCFProperty(platformExpert, CFSTR(kIOPlatformSerialNumberKey), kCFAllocatorDefault, 0);
        if (serialNumberAsCFString) {
            const char* serialStr = CFStringGetCStringPtr((CFStringRef)serialNumberAsCFString, kCFStringEncodingUTF8);
            if (serialStr) serial = serialStr;
            CFRelease(serialNumberAsCFString);
        }
        IOObjectRelease(platformExpert);
    }
    return serial;
}

std::string hwid::getVolumeSerial() {
    struct statfs stat;
    if (statfs("/", &stat) == 0) {
        return std::to_string(stat.f_fsid.val[0]);
    }
    return "N/A";
}

#elif __linux__
#include <fstream>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <cstring>
#include <sys/vfs.h>
#include "hwidchecks.h"

std::string hwid::getMACAddress() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return "N/A";

    struct ifconf ifc;
    char buf[1024];
    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {
        close(sock);
        return "N/A";
    }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
        std::string ifaceName = it->ifr_name;
        if (ifaceName == "lo") continue; // Skip loopback

        struct ifreq ifr;
        strcpy(ifr.ifr_name, ifaceName.c_str());
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
            char mac[18];
            sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
                (unsigned char)ifr.ifr_hwaddr.sa_data[0],
                (unsigned char)ifr.ifr_hwaddr.sa_data[1],
                (unsigned char)ifr.ifr_hwaddr.sa_data[2],
                (unsigned char)ifr.ifr_hwaddr.sa_data[3],
                (unsigned char)ifr.ifr_hwaddr.sa_data[4],
                (unsigned char)ifr.ifr_hwaddr.sa_data[5]);
            close(sock);
            return mac;
        }
    }
    close(sock);
    return "N/A";
}

std::string hwid::getMotherboardSerial() {
    std::ifstream file("/sys/class/dmi/id/board_serial");
    std::string serial;
    if (file.is_open()) {
        std::getline(file, serial);
        file.close();
        return serial;
    }
    return "N/A";
}

std::string hwid::getVolumeSerial() {
    struct statfs buf;
    if (statfs("/", &buf) == 0) {
        std::stringstream ss;
        ss << std::hex << buf.f_fsid.__val[0] << buf.f_fsid.__val[1];
        return ss.str();
    }
    return "N/A";
}

#endif