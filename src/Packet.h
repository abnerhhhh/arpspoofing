//
// Created by sun on 2026/10/20.
//

#ifndef ARPSPOOF_PACKET_H
#define ARPSPOOF_PACKET_H
#include <array>
#include <atomic>
#include <cstdint>
#include <map>
#include <pcap.h>

class Packet {

    public:
        struct Adapter {
                pcap_if_t *selected;
                uint8_t* srcMac = nullptr;
                uint8_t* srcIp = nullptr;
                uint8_t* targetIp = nullptr;
                uint32_t availableip = 0;
                pcap_t* rechandle=nullptr;
                pcap_t* reqhandle=nullptr;
                uint8_t subnetMask[4]{};
                std::atomic<bool> running{false};
                std::array<uint8_t, 4> gateway{};
                bool hasGateway = false;

        };

        struct Host {
            std::array<uint8_t, 4> ip;
            std::array<uint8_t, 6> mac;
        };

        static std::map<uint32_t, Host> arpTable;

        static Adapter adapter;
        static bool packet(pcap_if_t *selected, const std::array<uint8_t, 60>& packet);
        static bool sendrequest(uint8_t srcIp[4]);
        static void receivePackets();
        static uint32_t scanSubnet(
        const uint8_t srcIp[4],
        const uint8_t subnetMask[4]
        );
        static bool arprep(uint8_t target[4]);
        static bool arpscam(uint32_t ID);
        static void printHosts();


};


#endif //ARPSPOOF_PACKET_H
