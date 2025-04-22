#include <iostream>
#include <string>
#include <windows.h>
#include <intrin.h>
#include <sstream>
#include <iomanip>
#include <functional>
#include <wbemidl.h>
#include <comdef.h>
#include <iphlpapi.h>
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "iphlpapi.lib")

// Initialize COM and WMI
bool InitializeWMI(IWbemLocator** pLoc, IWbemServices** pSvc) {
    HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) return false;

    hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hres)) {
        CoUninitialize();
        return false;
    }

    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)pLoc);
    if (FAILED(hres)) {
        CoUninitialize();
        return false;
    }

    hres = (*pLoc)->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, 0, 0, 0, pSvc);
    if (FAILED(hres)) {
        (*pLoc)->Release();
        CoUninitialize();
        return false;
    }

    hres = CoSetProxyBlanket(*pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hres)) {
        (*pSvc)->Release();
        (*pLoc)->Release();
        CoUninitialize();
        return false;
    }
    return true;
}

// Query WMI for hardware info
std::string QueryWMI(IWbemServices* pSvc, const std::wstring& query, const std::wstring& property) {
    IEnumWbemClassObject* pEnumerator = NULL;
    HRESULT hres = pSvc->ExecQuery(_bstr_t(L"WQL"), _bstr_t(query.c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
    if (FAILED(hres)) return "WMI_ERROR";

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    std::string result = "NOT_FOUND";

    if (pEnumerator && SUCCEEDED(pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn)) && uReturn) {
        VARIANT vtProp;
        VariantInit(&vtProp);
        hres = pclsObj->Get(property.c_str(), 0, &vtProp, 0, 0);
        if (SUCCEEDED(hres) && vtProp.vt == VT_BSTR && vtProp.bstrVal) {
            _bstr_t bstr(vtProp.bstrVal);
            result = (const char*)bstr;
        }
        VariantClear(&vtProp);
        pclsObj->Release();
    }
    if (pEnumerator) pEnumerator->Release();
    return result.empty() ? "EMPTY" : result;
}

// Get Disk Serial Number
std::string GetDiskSerialNumber() {
    char volumeName[MAX_PATH], fileSystemName[MAX_PATH];
    DWORD serialNumber, maxComponentLen, fileSystemFlags;
    if (GetVolumeInformationA("C:\\", volumeName, MAX_PATH, &serialNumber,
        &maxComponentLen, &fileSystemFlags, fileSystemName, MAX_PATH)) {
        std::stringstream ss;
        ss << std::hex << std::uppercase << serialNumber;
        return ss.str();
    }
    return "DISK_ERROR";
}

// Get CPU ID
std::string GetCPUID() {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 1);
    std::stringstream ss;
    ss << std::hex << std::uppercase << cpuInfo[0] << cpuInfo[1] << cpuInfo[3];
    return ss.str();
}

// Get MAC Address
std::string GetMACAddress() {
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD dwBufLen = sizeof(adapterInfo);
    if (GetAdaptersInfo(adapterInfo, &dwBufLen) == ERROR_SUCCESS) {
        std::stringstream ss;
        for (int i = 0; i < adapterInfo[0].AddressLength; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)adapterInfo[0].Address[i];
            if (i < adapterInfo[0].AddressLength - 1) ss << ":";
        }
        return ss.str();
    }
    return "MAC_ERROR";
}

// Generate Combined HWID
std::string GenerateHWID(const std::string& disk, const std::string& cpu,
    const std::string& mb, const std::string& bios,
    const std::string& mac) {
    std::string combined = disk + cpu + mb + bios + mac;
    std::hash<std::string> hasher;
    size_t hash = hasher(combined);
    std::stringstream ss;
    ss << std::hex << std::uppercase << hash;
    return ss.str();
}

int main() {
    // Initialize WMI
    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;
    bool wmiInitialized = InitializeWMI(&pLoc, &pSvc);

    // Collect HWIDs
    std::string diskSerial = GetDiskSerialNumber();
    std::string cpuID = GetCPUID();
    std::string macAddress = GetMACAddress();
    std::string motherboardSerial = wmiInitialized ? QueryWMI(pSvc, L"SELECT SerialNumber FROM Win32_BaseBoard", L"SerialNumber") : "WMI_NOT_INIT";
    std::string biosSerial = wmiInitialized ? QueryWMI(pSvc, L"SELECT SerialNumber FROM Win32_BIOS", L"SerialNumber") : "WMI_NOT_INIT";

    // Display individual HWIDs
    std::cout << "Disk Serial Number: " << diskSerial << std::endl;
    std::cout << "CPU ID: " << cpuID << std::endl;
    std::cout << "MAC Address: " << macAddress << std::endl;
    std::cout << "Motherboard Serial: " << motherboardSerial << std::endl;
    std::cout << "BIOS Serial: " << biosSerial << std::endl;

    // Generate and display combined HWID
    std::string hwid = GenerateHWID(diskSerial, cpuID, motherboardSerial, biosSerial, macAddress);
    std::cout << "\nCombined HWID: " << hwid << std::endl;

    // Cleanup WMI
    if (pSvc) pSvc->Release();
    if (pLoc) pLoc->Release();
    if (wmiInitialized) CoUninitialize();

    // Keep console open
    std::cout << "\nPress Enter to exit..." << std::endl;
    std::cin.get();
    return 0;
}