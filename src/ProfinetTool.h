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

/**
 * ProfinetDevice models the parameters for a Profinet device
 */
struct ProfinetDevice {
    std::string deviceName;
    std::string deviceType;
    std::string ipAddress;
    std::string subnetMask;
    std::string gateway;
    std::array<uint8_t, 6> deviceMAC;
};

/**
 * ProfinetTool class contains the methods providing the core functionality of configuring a Profinet network
 */
class ProfinetTool {
public:
    /**
     * Construct ProfinetTool class using the default interface
     * @param timeout Timeout for searching for devices on network
     */
    explicit ProfinetTool(int timeout = 5000);

    /**
     * Construct ProfinetTool class
     * @param interface The interface to use to configure the Profinet netwoork
     * @param timeout Timeout for searching for devices on network
     */
    ProfinetTool(const std::string &interface, int timeout);

    /**
     * Search for devices on the Profinet network
     * @param printFoundDevices Print the devices found to stdout
     * @return A vector of found devices as a vector of type ProfinetDevice
     */
    std::vector<ProfinetDevice> searchForDevices(bool printFoundDevices = true);

    /**
     * Configure a device on the Profinet network
     *
     * Leave parameter blank ( empty string or std::string() ) if parameter should not be changed
     *
     * WARNING: Might fail if Subnet/Gateway settings do not match IP (bad response from device)
     *
     * @param deviceName The station name of the device to configure
     * @param newName The new station name of the device
     * @param newIP The new IP address of the device
     * @param newSubnet The new subnet mask of the device
     * @param newGateway The new gateway IP address of the device
     */
    void configureDevices(const std::string &deviceName, const std::string &newName, const std::string &newIP,
                          const std::string &newSubnet, const std::string &newGateway);

private:
    /**
     * Listens for Profinet packets on the specified interface
     * @return Thread for the packet listener
     */
    std::thread listenForPackets();

    std::string interface;
    int searchTimeout;

    profinet_packet_array profinetPacketArray{};
};


#endif //OPENPROFINET_PROFINETTOOL_H
