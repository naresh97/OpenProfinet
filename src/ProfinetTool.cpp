//
// Created by naresh on 31/10/2021.
//

#include <pcap/pcap.h>

#include <thread>
#include <iostream>
#include <cstring>
#include "ProfinetTool.h"

extern "C" {
#include "pcapInterface.h"
#include <arpa/inet.h>
}

#define LISTENING_THREAD_STARTUP_DELAY 500

std::string getDefaultInterface() {
    char interface[256];
    get_default_interface(interface);
    return interface;
}

std::string MACToString(std::array<uint8_t, 6> mac) {
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return macStr;
}

std::vector<ProfinetDevice> getDevicesFromPackets(profinet_packet_array profinetPacketArray) {
    profinet_device devices[PROFINET_DEVICE_LIST_SIZE];
    int count;

    std::vector<ProfinetDevice> devicesVector;
    get_profinet_devices(&profinetPacketArray, devices, &count);
    for (int i = 0; i < count; ++i) {
        auto device = devices[i];
        char ipAddress[INET_ADDRSTRLEN];
        char subnet[INET_ADDRSTRLEN];
        char gateway[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &device.ipAddress, ipAddress, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &device.subnetMask, subnet, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &device.gateway, gateway, INET_ADDRSTRLEN);

        ProfinetDevice newDevice{
                .deviceName = device.deviceName,
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

std::thread ProfinetTool::listenForPackets() {
    auto listeningThread = std::thread([this]() {
        profinet_listen(interface.c_str(), &profinetPacketArray, searchTimeout);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(LISTENING_THREAD_STARTUP_DELAY));
    return listeningThread;
}

std::vector<ProfinetDevice> ProfinetTool::searchForDevices(bool printFoundDevices) {
    profinetPacketArray = {.packets = {}, .size = 0};

    auto listeningThread = listenForPackets();

    discovery_request(interface.c_str());

    std::cout << "Searching for devices..." << std::endl;

    listeningThread.join();

    auto devices = getDevicesFromPackets(profinetPacketArray);

    if (printFoundDevices) {
        for (const auto &device: devices) {
            using namespace std;
            cout << "Device Name: " << device.deviceName << " - IP: " << device.ipAddress << ", Subnet Mask: "
                 << device.subnetMask
                 << ", Gateway: " << device.gateway << ", Type: " << device.deviceType << endl;
        }
    }

    return devices;
}

void ProfinetTool::configureDevices(const std::string &deviceName, const std::string &newName, const std::string &newIP,
                                    const std::string &newSubnet, const std::string &newGateway) {
    auto devices = searchForDevices(false);

    ProfinetDevice device;
    bool found = false;
    for (auto const &loopDevice: devices) {
        if (loopDevice.deviceName == deviceName) {
            found = true;
            device = loopDevice;
            break;
        }
    }

    if (!found) throw std::runtime_error("Device does not exist on network. Use 'search' to check the name.");

    if (!newName.empty()) device.deviceName = newName;
    if (!newIP.empty()) device.ipAddress = newIP;
    if (!newSubnet.empty()) device.subnetMask = newSubnet;
    if (!newGateway.empty()) device.gateway = newGateway;

    profinet_device device_p{};
    strcpy(device_p.deviceName, device.deviceName.c_str());
    strcpy(device_p.deviceType, device.deviceType.c_str());
    memcpy(device_p.macAddress, device.deviceMAC.data(), 6);
    inet_pton(AF_INET, device.ipAddress.c_str(), &device_p.ipAddress);
    inet_pton(AF_INET, device.subnetMask.c_str(), &device_p.subnetMask);
    inet_pton(AF_INET, device.gateway.c_str(), &device_p.gateway);

    auto success = set_device_configuration(interface.c_str(), &device_p);
    if (success)
        std::cout << "Device Configuration: Success!" << std::endl << std::endl;
    else
        throw std::runtime_error("Configuration Failure. Did not receive response from the device.");
    searchForDevices(true);
}

ProfinetTool::ProfinetTool(const std::string &interface, int timeout) : interface(interface), searchTimeout(timeout) {}

ProfinetTool::ProfinetTool(int timeout) : interface(getDefaultInterface()), searchTimeout(timeout) {
    std::cout << "Using default interface: " << getDefaultInterface() << std::endl;
}
