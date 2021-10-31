//
// Created by naresh on 31/10/2021.
//

#ifndef OPENPROFINET_PROFINETTOOL_H
#define OPENPROFINET_PROFINETTOOL_H

#include <string>
#include <vector>
#include <array>

struct ProfinetDevice{
    std::string deviceName;
    std::string deviceType;
    std::string ipAddress;
    std::string subnetMask;
    std::string gateway;
    std::array<uint8_t, 6> deviceMAC;
};

class ProfinetTool {
public:
    explicit ProfinetTool(const std::string &interface);
    void searchForDevices();
    void setDeviceProperties();

private:
    std::string interface;
};


#endif //OPENPROFINET_PROFINETTOOL_H
