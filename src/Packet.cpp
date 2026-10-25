//
// Created by sun on 2026/10/20.
//
#include <pcap.h>
#include <iostream>
#include <array>
#include <cstring>
#include <cstdint>
#include "adapters.h"
#pragma comment(lib, "Iphlpapi.lib")
#include "Packet.h"
#include <thread>
#include <chrono>
#include <cstdio>
#include <algorithm>
Packet::Adapter Packet::adapter{};
std::map<uint8_t, Packet::Host> Packet::arpTable{};

bool Packet::packet(pcap_if_t *selected,std::array<uint8_t, 60> packet) {



    char errbuf[PCAP_ERRBUF_SIZE] = {};

    pcap_t* handle = pcap_open_live(
        selected->name, 65536, 0, 1000, errbuf
    );

    if (!handle) {
        std::cerr << errbuf << '\n';

        return true;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        std::cerr << "Not an Ethernet adapter\n";
        pcap_close(handle);

        return true;
    }

    // Example only: replace with the actual adapter MAC and IP.

    adapter.reqhandle=handle;


    int result = pcap_sendpacket(
        handle,
        packet.data(),
        static_cast<int>(packet.size())
    );

    if (result == 0) {

        return false;

    }
    else {
        std::cerr << pcap_geterr(handle) << '\n';
    }



    return result == 0 ? 0 : 1;
}

bool Packet::sendrequest(uint8_t targetIp[4]) {

    std::array<uint8_t, 60> packet{};

    // Ethernet destination: broadcast
    std::memset(packet.data(), 0xff, 6);
    std::memcpy(packet.data() + 6, adapter.srcMac, 6);

    packet[12] = 0x08;
    packet[13] = 0x06; // ARP

    // ARP header
    packet[14] = 0x00; packet[15] = 0x01; // Ethernet
    packet[16] = 0x08; packet[17] = 0x00; // IPv4
    packet[18] = 6;    // MAC length
    packet[19] = 4;    // IP length
    packet[20] = 0; packet[21] = 1; // ARP Request

    std::memcpy(packet.data() + 22, adapter.srcMac, 6);
    std::memcpy(packet.data() + 28, adapter.srcIp, 4);
    // Target MAC remains zero
    std::memcpy(packet.data() + 38, targetIp, 4);




    return Packet::packet(adapter.selected, packet);
}




void Packet::receivePackets() {

    char errbuf[PCAP_ERRBUF_SIZE]{};
    struct pcap_pkthdr* header;
    const u_char* packet;
    pcap_t* handle = pcap_open_live(
        adapter.selected->name, 65536, 0, 1000, errbuf
    );
    adapter.rechandle=handle;
    while (adapter.running.load()) {
        std::array<uint8_t, 4> ipAddr{};
        std::array<uint8_t, 6> macAddr{};


        int result = pcap_next_ex(
            handle,
            &header,
            &packet
        );

        if (result == 0) {
            continue; // Timeout
        }

        if (result == -2) {
            break; // End of capture
        }

        if (result == -1) {
            printf("Error: %s\n", pcap_geterr(handle));
            break;
        }

        //printf("\nReceived %u bytes\n", header->caplen);

        if (header->caplen < 42) {
            continue;
        }

        // Ethernet Type: ARP = 0x0806
        if (packet[12] != 0x08 || packet[13] != 0x06) {
            continue;
        }

        // ARP opcode
        uint16_t opcode =
            (uint16_t(packet[20]) << 8) | packet[21];

        if (opcode != 2) {
            continue;
        }

        if (packet[28]==adapter.srcIp[0]&& packet[29]==adapter.srcIp[1]&& packet[30]==adapter.srcIp[2]&& packet[31]==adapter.srcIp[3]) {
            continue;
        }

        uint8_t ip[4]={
            packet[28], packet[29],
            packet[30], packet[31]
        };

        uint8_t mac[6] = {packet[22], packet[23], packet[24],
            packet[25], packet[26], packet[27]};

        Host host{};

        std::copy_n(ip, 4, host.ip.begin());
        std::copy_n(mac, 6, host.mac.begin());
        uint8_t id = static_cast<uint8_t>(arpTable.size() + 1);

        arpTable[id] = host;
        printf("ARP Opcode: %u\n", opcode);

        printf("Target IP: %u.%u.%u.%u\n",
            packet[28], packet[29],
            packet[30], packet[31]);

        printf("Target MAC: %02X:%02X:%02X:%02X:%02X:%02X\n-----------------------------------------------------------\n",
            packet[22], packet[23], packet[24],
            packet[25], packet[26], packet[27]);
    }
}

uint32_t Packet::scanSubnet(
    const uint8_t srcIp[4],
    const uint8_t subnetMask[4]
) {
    uint32_t ip = 0;
    uint32_t mask = 0;

    // Convert IPv4 bytes to uint32_t
    for (int i = 0; i < 4; i++) {
        ip = (ip << 8) | srcIp[i];
        mask = (mask << 8) | subnetMask[i];
    }

    uint32_t network = ip & mask;
    uint32_t broadcast = network | ~mask;

    // Exclude network and broadcast addresses
    if (broadcast - network <= 1)
        return 0;

    for (uint32_t current = network + 1;
         current < broadcast;
         current++) {

        uint8_t targetIp[4] = {
            static_cast<uint8_t>(current >> 24),
            static_cast<uint8_t>(current >> 16),
            static_cast<uint8_t>(current >> 8),
            static_cast<uint8_t>(current)
        };

        // Skip local IP
        if (current == ip)
            continue;


        if (!Packet::sendrequest(targetIp))
            //printf("\rTarget: %u.%u.%u.%u ARP Request sent",targetIp[0],targetIp[1],targetIp[2],targetIp[3]);

        std::this_thread::sleep_for(
        std::chrono::milliseconds(50)
       );

        // Build ARP Request for targetIp
        // Send packet using Packet::send(...)

         }
    return 0;

}

bool Packet::arprep(uint8_t target[4]) {

    std::array<uint8_t, 60> packet{};

    // Ethernet destination: broadcast
    std::memset(packet.data(), 0xff, 6);
    std::memcpy(packet.data() + 6, adapter.srcMac, 6);

    packet[12] = 0x08;
    packet[13] = 0x06; // ARP

    // ARP header
    packet[14] = 0x00; packet[15] = 0x01; // Ethernet
    packet[16] = 0x08; packet[17] = 0x00; // IPv4
    packet[18] = 6;    // MAC length
    packet[19] = 4;    // IP length
    packet[20] = 0; packet[21] = 2; // ARP Reply

    std::memcpy(packet.data() + 22, adapter.srcMac, 6);
    std::memcpy(packet.data() + 28, adapter.gateway, 4);
    // Target MAC remains zero
    std::memcpy(packet.data() + 38, target, 4);




    return Packet::packet(adapter.selected, packet);
}

void Packet::arpscam(uint32_t ID) {
    uint8_t target[4];
    //uint8_t mac[6];
    for (const auto& [id, host] : arpTable) {

        if (static_cast<unsigned>(id)==ID) {
            for (int i=0; i<4; i++) {
                target[i]=host.ip[i];
            }
            /*for (int i=0; i<6; i++) {
                mac[i]=host.mac[i];
            }*/
        }

    }
    Packet::arprep(target);

}

#include <iostream>
#include <iomanip>

void Packet::printHosts() {


    printf("%-5s %-18s %s\n", "ID", "IP Address", "MAC Address");

    for (const auto& [id, host] : arpTable) {
        char ipStr[16];

        snprintf(ipStr, sizeof(ipStr),
                 "%u.%u.%u.%u",
                 host.ip[0], host.ip[1],
                 host.ip[2], host.ip[3]);

        printf("%-5u %-18s ",
               static_cast<unsigned>(id), ipStr);

        for (int i = 0; i < 6; i++) {
            printf("%02x%s",
                   static_cast<unsigned>(host.mac[i]),
                   i == 5 ? "" : ":");
        }

        printf("\n");
    }

}