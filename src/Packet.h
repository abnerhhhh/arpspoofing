//
// Created by sun on 2026/10/20.
//

#ifndef ARPSPOOF_PACKET_H
#define ARPSPOOF_PACKET_H
#include <map>

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
                uint8_t subnetMask[4];
                std::atomic<bool> running;
                uint8_t* gateway=nullptr;

        };

        struct Host {
            std::array<uint8_t, 4> ip;
            std::array<uint8_t, 6> mac;
        };

        static std::map<uint8_t, Host> arpTable;

        static Adapter adapter;
        static bool packet(pcap_if_t *selected,std::array<uint8_t, 60> packet);
        static bool sendrequest(uint8_t srcIp[4]);
        static void receivePackets();
        static uint32_t scanSubnet(
        const uint8_t srcIp[4],
        const uint8_t subnetMask[4]
        );
        static bool arprep(uint8_t target[4]);
        static void arpscam(uint32_t ID);
        static void printHosts();


};


#endif //ARPSPOOF_PACKET_H