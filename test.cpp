#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

#include <vector>
#include <array>
#include <string>
#include <iostream>
#include <iomanip>


#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")


std::string WideToUTF8(const wchar_t* wstr) {
    if (wstr == nullptr)
        return "";

    int size = WideCharToMultiByte(
        CP_UTF8,
        0,
        wstr,
        -1,
        nullptr,
        0,
        nullptr,
        nullptr
    );

    if (size == 0)
        return "";

    std::string result(size, '\0');

    WideCharToMultiByte(
        CP_UTF8,
        0,
        wstr,
        -1,
        result.data(),
        size,
        nullptr,
        nullptr
    );

    result.pop_back(); // Remove null terminator
    return result;
}
int main() {
    SetConsoleOutputCP(CP_UTF8);
    ULONG bufferSize = 150000;
    std::vector<unsigned char> buffer(bufferSize);

    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;

    DWORD result = GetAdaptersAddresses(
        AF_UNSPEC,
        flags,
        nullptr,
        reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()),
        &bufferSize
    );

    if (result != NO_ERROR) {
        std::cerr << "GetAdaptersAddresses failed: "
                  << result << std::endl;
        return 1;
    }

    auto* adapter =
        reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());

    int index = 0;

    for (; adapter != nullptr; adapter = adapter->Next) {
        ++index;
        std::cout << "Adapter: "
                  << adapter->AdapterName << std::endl;

        std::cout << "Friendly Name: "
          << WideToUTF8(adapter->FriendlyName)
          << std::endl;

        std::cout << "MAC Length: "
                  << adapter->PhysicalAddressLength << std::endl;

        std::cout << "MAC: ";

        for (ULONG i = 0; i < adapter->PhysicalAddressLength; i++) {
            if (i > 0)
                std::cout << ':';

            std::cout << std::hex
                      << std::setw(2)
                      << std::setfill('0')
                      << static_cast<unsigned int>(
                             adapter->PhysicalAddress[i]);
        }

        std::cout << std::dec << std::endl;
        std::cout << "----------------------" << std::endl;
    }

    return 0;
}