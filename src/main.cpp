
#include <pcap.h>
#include <iostream>
#include <array>
#include <cstring>
#include <cstdint>
#include "adapters.h"
#pragma comment(lib, "Iphlpapi.lib")
int main() {
    SetConsoleOutputCP(CP_UTF8);
    uint8_t srcIp[4];
    const uint8_t targetIp[4] = {172, 20, 10, 1};

    uint32_t availableip;
    uint8_t srcMac[6];
    uint8_t Mask[4];
    uint8_t* ptr = srcMac;
    uint8_t* maskptr = Mask;
    uint32_t* ipptr=&availableip;

    char errbuf[PCAP_ERRBUF_SIZE] = {};
    pcap_if_t* devices = nullptr;

    if (pcap_findalldevs(&devices, errbuf) != 0) {
        std::cerr << errbuf << '\n';
        return 1;
    }



    int index = 0;
    for (auto* d = devices; d; d = d->next) {
        std::cout << ++index << ": " << d->name << '\n';
        adapters::getAdapterNames(d->name);
    }

    int choice;
    std::cout << "Select adapter: ";
    if (!(std::cin >> choice) || choice < 1 || choice > index) {
        pcap_freealldevs(devices);
        return 1;
    }
//---------------------------------------------------------------------------------------------
    auto* selected = devices;
    for (int i = 1; i < choice; ++i)
        selected = selected->next;

    std::cout << "Selected adapter: "
          << selected->name << std::endl;





    adapters::getMac(ptr,selected->name);

    if (adapters::getIp(selected,srcIp)) {
        printf("IP: %u.%u.%u.%u\n",
           srcIp[0],
           srcIp[1],
           srcIp[2],
           srcIp[3]);
    }
    else {
        std::cerr << "ipv4 not found" << '\n';
    }

    availableip=adapters::getsubnetMask(selected);

    std::cout << "availableip: " << availableip << std::endl;

    pcap_t* handle = pcap_open_live(
        selected->name, 65536, 0, 1000, errbuf
    );

    if (!handle) {
        std::cerr << errbuf << '\n';
        pcap_freealldevs(devices);
        return 1;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        std::cerr << "Not an Ethernet adapter\n";
        pcap_close(handle);
        pcap_freealldevs(devices);
        return 1;
    }

    // Example only: replace with the actual adapter MAC and IP.


    std::array<uint8_t, 60> packet{};

    // Ethernet destination: broadcast
    std::memset(packet.data(), 0xff, 6);
    std::memcpy(packet.data() + 6, srcMac, 6);

    packet[12] = 0x08;
    packet[13] = 0x06; // ARP

    // ARP header
    packet[14] = 0x00; packet[15] = 0x01; // Ethernet
    packet[16] = 0x08; packet[17] = 0x00; // IPv4
    packet[18] = 6;    // MAC length
    packet[19] = 4;    // IP length
    packet[20] = 0; packet[21] = 1; // ARP Request

    std::memcpy(packet.data() + 22, srcMac, 6);
    std::memcpy(packet.data() + 28, srcIp, 4);
    // Target MAC remains zero
    std::memcpy(packet.data() + 38, targetIp, 4);

    int result = pcap_sendpacket(
        handle,
        packet.data(),
        static_cast<int>(packet.size())
    );

    if (result == 0)
        std::cout << "ARP Request sent\n";
    else
        std::cerr << pcap_geterr(handle) << '\n';

    pcap_close(handle);
    pcap_freealldevs(devices);
    return result == 0 ? 0 : 1;
    
}
