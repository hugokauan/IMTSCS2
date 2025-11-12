#include "hwidchecks.h"

hwid hwidChecker;



std::string macAdress = hwidChecker.getMACAddress();
std::string motherboardSerial = hwidChecker.getMotherboardSerial();
std::string diskHwid = hwidChecker.getVolumeSerial();



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