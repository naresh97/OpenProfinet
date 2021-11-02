//
// Created by naresh on 31/10/2021.
//

#ifndef OPENPROFINET_PROFINETTYPES_H
#define OPENPROFINET_PROFINETTYPES_H

#include <netinet/in.h>

#define DEVICE_NAME_LENGTH 128
#define DEVICE_TYPE_LENGTH 128
#define PACKET_ARRAY_SIZE 256
#define PACKET_DATA_BLOCK_SIZE 256
#define DCP_BLOCK_SIZE 128

struct profinet_device {
    char deviceName[DEVICE_NAME_LENGTH];
    char deviceType[DEVICE_TYPE_LENGTH];
    in_addr_t ipAddress;
    in_addr_t subnetMask;
    in_addr_t gateway;
    uint8_t macAddress[6];
};

struct profinet_dcp_header {
    uint16_t frameId;
    uint8_t serviceId;
    uint8_t serviceType;
    uint32_t transactionId;
    uint16_t responseDelay;
    uint16_t dataLength;
} __attribute__ ((__packed__));

struct profinet_dcp_block_header {
    uint8_t option;
    uint8_t subOption;
    uint16_t blockLength;
    uint16_t blockInfo;
} __attribute__ ((__packed__));

struct profinet_dcp_block {
    struct profinet_dcp_block_header header;
    unsigned char data[DCP_BLOCK_SIZE];
    size_t dataLength;
};


struct profinet_packet {
    struct profinet_dcp_header dcpHeader;
    unsigned char dataBlock[PACKET_DATA_BLOCK_SIZE];
    uint8_t sourceMACAddress[6];
};

struct profinet_packet_array {
    struct profinet_packet packets[PACKET_ARRAY_SIZE];
    size_t size;
};

struct profinet_dcp_block_ip_s {
    uint8_t option;
    uint8_t suboption;
    uint16_t length;
    uint16_t qualifier;
    uint32_t ip_address;
    uint32_t subnet_mask;
    uint32_t standard_gateway;
} __attribute__ ((__packed__));

#endif //OPENPROFINET_PROFINETTYPES_H
