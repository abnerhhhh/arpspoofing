//
// Created by sun on 2026/10/19.
//

#ifndef ARPSPOOF_ADAPTERS_H
#define ARPSPOOF_ADAPTERS_H

#include <cstdint>
#include <string>

#include "pcap/pcap.h"

class adapters {
public:
    static void getAdapterNames(const std::string& pcapName);

    static void getMac(uint8_t *macptr, const std::string &pcapName);

    static uint32_t getsubnetMask(pcap_if_t* selected);

    static bool getIp(pcap_if_t* selected, uint8_t* srcIp);
};

#endif // ARPSPOOF_ADAPTERS_H