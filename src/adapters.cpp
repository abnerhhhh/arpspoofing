//
// Created by sun on 2026/10/19.
//

#include "adapters.h"
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

#include "pcap/pcap.h"

#include "Packet.h"
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
void adapters::getAdapterNames(

    const std::string& pcapName
) {

    const std::string prefix = R"(\Device\NPF_)";
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

    }

    auto* adapter =
        reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());

    int index = 0;
    if (pcapName.rfind(prefix, 0) == 0) {
        std::string guid = pcapName.substr(prefix.size());

        for (; adapter != nullptr; adapter = adapter->Next) {
            ++index;
            if (_stricmp(adapter->AdapterName, guid.c_str()) == 0) {
                //std::cout << "Adapter: "<< adapter->AdapterName << std::endl;

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
                //std::memcpy(macptr, mac, 6);
                std::cout << std::dec << std::endl;
                std::cout << "----------------------" << std::endl;
            }

        }
    }



}

void adapters::getMac(
    uint8_t* macptr,
    const std::string& pcapName
) {
    if (!macptr)
        return;

    uint8_t* gateptr;
    const std::string prefix = R"(\Device\NPF_)";

    ULONG bufferSize = 15000;
    std::vector<unsigned char> buffer(bufferSize);

    ULONG flags =
        GAA_FLAG_INCLUDE_PREFIX |
        GAA_FLAG_INCLUDE_GATEWAYS;

    DWORD result = GetAdaptersAddresses(
        AF_INET,
        flags,
        nullptr,
        reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()),
        &bufferSize
    );

    if (result == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(bufferSize);

        result = GetAdaptersAddresses(
            AF_INET,
            flags,
            nullptr,
            reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()),
            &bufferSize
        );
    }

    if (result != NO_ERROR) {
        std::cerr << "GetAdaptersAddresses failed: "
                  << result << '\n';
        return;
    }

    if (pcapName.rfind(prefix, 0) != 0) {
        std::cerr << "Invalid Npcap adapter name\n";
        return;
    }

    std::string guid = pcapName.substr(prefix.size());

    auto* adapter =
        reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());

    for (; adapter != nullptr; adapter = adapter->Next) {

        if (_stricmp(adapter->AdapterName, guid.c_str()) != 0)
            continue;

        std::cout << "Adapter: "
                  << adapter->AdapterName << '\n';

        std::cout << "Friendly Name: "
                  << WideToUTF8(adapter->FriendlyName)
                  << '\n';

        // Get MAC
        if (adapter->PhysicalAddressLength != 6) {
            std::cerr << "Invalid MAC length\n";
            return;
        }

        std::memcpy(macptr, adapter->PhysicalAddress, 6);

        printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               macptr[0], macptr[1], macptr[2],
               macptr[3], macptr[4], macptr[5]);

        // Get Default Gateway
        bool foundGateway = false;

        for (auto* gw = adapter->FirstGatewayAddress;
             gw != nullptr;
             gw = gw->Next) {

            if (!gw->Address.lpSockaddr ||
                gw->Address.lpSockaddr->sa_family != AF_INET)
                continue;

            auto* addr = reinterpret_cast<sockaddr_in*>(
                gw->Address.lpSockaddr
            );

            uint8_t gateway[4]{};

            std::memcpy(gateptr, &addr->sin_addr, 4);

            if (Packet::adapter.gateway != nullptr &&
                Packet::adapter.gateway != nullptr) {
                Packet::adapter.gateway=gateptr;
            }

            printf("Default Gateway: %u.%u.%u.%u\n",
                   gateway[0], gateway[1],
                   gateway[2], gateway[3]);

            foundGateway = true;
            break;
        }

        if (!foundGateway) {
            std::cout << "No IPv4 Default Gateway\n";
        }

        return;
    }

    std::cerr << "Adapter not found\n";
}

uint32_t adapters::getsubnetMask(pcap_if_t* selected) {
    for (pcap_addr_t* a = selected->addresses;
     a != nullptr;
     a = a->next) {

        if (!a->addr || a->addr->sa_family != AF_INET)
            continue;

        if (!a->netmask || a->netmask->sa_family != AF_INET)
            continue;

        auto* mask = reinterpret_cast<sockaddr_in*>(a->netmask);

        uint8_t subnetMask[4];
        memcpy(subnetMask, &mask->sin_addr, 4);
        memcpy(Packet::adapter.subnetMask, subnetMask, 4);

        printf("Mask: %u.%u.%u.%u\n",
               subnetMask[0], subnetMask[1],
               subnetMask[2], subnetMask[3]);

        uint32_t Mask =
        (uint32_t(subnetMask[0]) << 24) |
        (uint32_t(subnetMask[1]) << 16) |
        (uint32_t(subnetMask[2]) << 8)  |
         uint32_t(subnetMask[3]);

        return  ~(Mask)-1;


     }
    return 0;

}

bool adapters::getIp(pcap_if_t* selected, uint8_t* srcIp) {
    if (!selected || !srcIp)
        return false;
    for (pcap_addr_t* a = selected->addresses;
         a != nullptr;
         a = a->next) {

        if (!a->addr || a->addr->sa_family != AF_INET)
            continue;

        auto* ipv4 = reinterpret_cast<sockaddr_in*>(a->addr);

        memcpy(srcIp, &ipv4->sin_addr, 4);

        return true;
         }
    return false;



}