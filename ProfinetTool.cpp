//
// Created by naresh on 31/10/2021.
//

#include <pcap/pcap.h>

#include <thread>
#include <iostream>
#include "ProfinetTool.h"

extern "C"{
#include "pcapInterface.h"
}

std::string MACToString(std::array<uint8_t, 6> mac){
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return macStr;
}

std::vector<ProfinetDevice> getDevicesFromPackets(profinet_packet_array profinetPacketArray){
    profinet_device devices[PROFINET_DEVICE_LIST_SIZE];
    int count;

    std::vector<ProfinetDevice> devicesVector;
    getProfinetDevices(&profinetPacketArray, devices, &count);
    for(int i = 0; i < count; ++i){
        auto device = devices[i];
        char ipAddress[INET_ADDRSTRLEN];
        char subnet[INET_ADDRSTRLEN];
        char gateway[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &device.ipAddress, ipAddress, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &device.subnetMask, subnet, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &device.gateway, gateway, INET_ADDRSTRLEN);

        ProfinetDevice newDevice{
            .deviceName = device.stationName,
            .deviceType = device.deviceType,
            .ipAddress = ipAddress,
            .subnetMask = subnet,
            .gateway = gateway,
        };
        std::copy(std::begin(device.macAddress), std::end(device.macAddress), std::begin(newDevice.deviceMAC));

        devicesVector.push_back(newDevice);
    }
    return devicesVector;
}

void ProfinetTool::searchForDevices() {
    profinet_packet_array profinetPacketArray{};
    auto listeningThread = std::thread([this, &profinetPacketArray](){
        profinetListen(interface.c_str(), &profinetPacketArray);
    });

    discoveryRequest(interface.c_str());

    listeningThread.join();

    auto devices = getDevicesFromPackets(profinetPacketArray);
    for(const auto &device : devices){
        using namespace std;
        cout << "Device Name: " << device.deviceName << " - IP: " << device.ipAddress << ", Subnet Mask: " << device.subnetMask
             << ", Gateway: " << device.gateway << ", Type: " << device.deviceType << endl;
    }
}

ProfinetTool::ProfinetTool(const std::string &interface) : interface(interface) {}
