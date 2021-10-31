//
// Created by naresh on 31/10/2021.
//

#ifndef OPENPROFINET_PROFINETTYPES_H
#define OPENPROFINET_PROFINETTYPES_H

struct profinet_device
{
    char stationName[128];
    char deviceType[128];
    in_addr_t ipAddress;
    in_addr_t subnetMask;
    in_addr_t gateway;
    uint8_t macAddress[6];
};

struct profinet_dcp_header
{
    uint16_t frameId;
    uint8_t serviceId;
    uint8_t serviceType;
    uint32_t transactionId;
    uint16_t responseDelay;
    uint16_t dataLength;
} __attribute__ ((__packed__));

struct profinet_dcp_block_header
{
    uint8_t option;
    uint8_t subOption;
    uint16_t blockLength;
    uint16_t blockInfo;
} __attribute__ ((__packed__));

struct profinet_dcp_block
{
    struct profinet_dcp_block_header header;
    unsigned char data[128];
    size_t dataLength;
};


struct profinet_packet
{
    struct profinet_dcp_header dcpHeader;
    unsigned char dataBlock[256];
    uint8_t sourceMACAddress[6];
};

struct profinet_packet_array
{
    struct profinet_packet packets[256];
    size_t size;
};

#endif //OPENPROFINET_PROFINETTYPES_H
