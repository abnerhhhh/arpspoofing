
#include <pcap.h>
#include <iostream>
#include <array>
#include <cstring>
#include <cstdint>
#include "adapters.h"
#include "Packet.h"
#include <windows.h>
#include <thread>
#pragma comment(lib, "Iphlpapi.lib")
int main() {
    SetConsoleOutputCP(CP_UTF8);
    uint8_t srcIp[4];
    uint8_t targetIp[4] = {192, 168, 0, 1};

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





    adapters::getMac(ptr,selected->name);//GET MAC

    if (adapters::getIp(selected,srcIp)) {//GET SRC IP
        printf("IP: %u.%u.%u.%u\n",
           srcIp[0],
           srcIp[1],
           srcIp[2],
           srcIp[3]);
    }
    else {
        std::cerr << "ipv4 not found" << '\n';
    }

    printf("tarIP: %u.%u.%u.%u\n",
           targetIp[0],
           targetIp[1],
           targetIp[2],
           targetIp[3]);


    availableip=adapters::getsubnetMask(selected);//GET availableip



    Packet::adapter.availableip=*ipptr;

    Packet::adapter.srcMac=ptr;

    Packet::adapter.srcIp=srcIp;

    Packet::adapter.targetIp=targetIp;

    Packet::adapter.selected=selected;



    std::cout << "availableip: " << availableip << std::endl;

    /*if (Packet::scanSubnet(srcIp,Packet::adapter.subnetMask)) {
            std::cout << "Packet sent" << std::endl;
    }
    else {
            std::cerr << "Packet not sent" << std::endl;
        }

    Sleep(1000); // 暫停 1 秒 (1000 毫秒)*/
    Packet::adapter.running = true;
    std::thread sender(&Packet::scanSubnet,srcIp,Packet::adapter.subnetMask);
    std::thread receiver(&Packet::receivePackets);

    sender.join();  // 等待 scanSubnet() 完成

    std::this_thread::sleep_for(
        std::chrono::milliseconds(5000)
    );              // 再等待 0.5 秒接收剩餘 ARP Reply

    Packet::adapter.running = false; // 通知接收執行緒停止
    receiver.join(); // 等待接收執行緒結束

    Packet::printHosts();
    uint8_t a;
    std::cin>>a;

    while (true) {
        Packet::arpscam(a);
    }






    return 0;
    
}
