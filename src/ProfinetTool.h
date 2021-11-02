//
// Created by naresh on 31/10/2021.
//

#ifndef OPENPROFINET_PROFINETTOOL_H
#define OPENPROFINET_PROFINETTOOL_H

#include <string>
#include <vector>
#include <array>
#include <thread>
#include "profinetTypes.h"

struct ProfinetDevice {
    std::string deviceName;
    std::string deviceType;
    std::string ipAddress;
    std::string subnetMask;
    std::string gateway;
    std::array<uint8_t, 6> deviceMAC;
};

class ProfinetTool {
public:
    explicit ProfinetTool(int timeout = 5000);

    ProfinetTool(const std::string &interface, int timeout);

    // Commands
    std::vector<ProfinetDevice> searchForDevices(bool printFoundDevices = true);

    void configureDevices(const std::string &deviceName, const std::string &newName, const std::string &newIP,
                          const std::string &newSubnet, const std::string &newGateway);

private:
    std::thread listenForPackets();

    std::string interface;
    int searchTimeout;

    profinet_packet_array profinetPacketArray{};
};


#endif //OPENPROFINET_PROFINETTOOL_H
