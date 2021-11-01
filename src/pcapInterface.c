//
// Created by naresh on 30/10/2021.
//

#include "pcapInterface.h"
#include <net/ethernet.h>
#include <memory.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <pthread.h>
#include <unistd.h>

#define DCP_BLOCK_IDENTIFY_SELECT_ALL {0xff, 0xff, 0x00, 0x00}
#define DEST_MAC_MULTICAST {0x01, 0x0e, 0xcf, 0x00, 0x00, 0x00}
#define VLAN_HEADER {0x00, 0x00, 0x88, 0x92}

#define DCP_BLOCK_CONTROL_END_TRANSACTION {0x05, 0x02, 0x00, 0x02, 0x00, 0x01}

void getInterfaceMACAddress(const char interface[], uint8_t *MACAddress) {
    struct ifreq s;
    strcpy(s.ifr_name, interface);
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd == -1) return;
    if (ioctl(fd, SIOCGIFHWADDR, &s) == 0) {
        memcpy(MACAddress, s.ifr_hwaddr.sa_data, 6);
    }
}

void printBytes(unsigned char *pointer, unsigned long length) {
    for (int i = 0; i < length; ++i) {
        printf("%02X ", pointer[i]);
    }
}

void getDCPBlocks(const unsigned char *blocks, size_t blocksLength, struct profinet_dcp_block *processedBlocks,
                  size_t *numberOfBlocks) {
    int blockCount = 0;
    unsigned long previousBlockSizes = 0;
    while (1) {

        if (previousBlockSizes >= blocksLength) break;

        struct profinet_dcp_block_header blockHeader;
        memcpy(&blockHeader, blocks + previousBlockSizes, sizeof(struct profinet_dcp_block_header));
        blockHeader.blockLength = ntohs(blockHeader.blockLength);

        if (blockHeader.blockLength == 0) break;

        unsigned char blockData[blockHeader.blockLength - 2];
        memcpy(&blockData, blocks + sizeof(blockHeader) + previousBlockSizes, sizeof(blockData));

        unsigned long blockDataSizeWithPadding = sizeof(blockHeader) + sizeof(blockData);
        if (blockDataSizeWithPadding % 2 != 0) blockDataSizeWithPadding += 1;

        previousBlockSizes += blockDataSizeWithPadding;

        memcpy(&processedBlocks[blockCount].header, &blockHeader, sizeof(blockHeader));
        memcpy(&processedBlocks[blockCount].data, &blockData, sizeof(blockData));
        processedBlocks[blockCount].dataLength = sizeof(blockData);

        blockCount++;
    }
    *numberOfBlocks = blockCount;
}

struct profinet_device getIdentifyResponse(const unsigned char *blocks, size_t blocksLength) {
    struct profinet_device response;
    struct profinet_dcp_block processBlocks[15];
    size_t numberOfBlocks;
    getDCPBlocks(blocks, blocksLength, processBlocks, &numberOfBlocks);
    for (int i = 0; i < numberOfBlocks; ++i) {
        if (processBlocks[i].header.option == 2 && processBlocks[i].header.subOption == 2) {
            memcpy(response.deviceName, processBlocks[i].data, processBlocks[i].dataLength);
        } else if (processBlocks[i].header.option == 1 && processBlocks[i].header.subOption == 2) {
            memcpy(&response.ipAddress, processBlocks[i].data, sizeof(in_addr_t));
            memcpy(&response.subnetMask, processBlocks[i].data + sizeof(in_addr_t), sizeof(in_addr_t));
            memcpy(&response.gateway, processBlocks[i].data + 2 * sizeof(in_addr_t), sizeof(in_addr_t));
        } else if (processBlocks[i].header.option == 2 && processBlocks[i].header.subOption == 1) {
            memcpy(response.deviceType, processBlocks[i].data, processBlocks[i].dataLength);
        }
        //printf("Option: %d, Suboption %d, Length: %d\n", processBlocks[i].header.option, processBlocks[i].header.subOption, processBlocks[i].header.blockLength);
    }
    return response;
}

void profinetCallback(unsigned char *args, const struct pcap_pkthdr *packetInfo, const unsigned char *packet) {
    static int count = 0;

    struct ether_header header;
    memcpy(&header, packet, sizeof(header));

    if (header.ether_type != htons(ETH_P_8021Q)) return;

    const int packetLength = packetInfo->len;

    const int profinetPacketSize = packetLength - (int) sizeof(struct ether_header) - 4;

    unsigned char profinetPacketRaw[profinetPacketSize];
    memcpy(profinetPacketRaw, packet + sizeof(struct ether_header) + 4, profinetPacketSize);

    struct profinet_dcp_header dcpHeader;
    memcpy(&dcpHeader, profinetPacketRaw, sizeof(dcpHeader));
    dcpHeader.frameId = ntohs(dcpHeader.frameId);
    dcpHeader.transactionId = ntohl(dcpHeader.transactionId);
    dcpHeader.dataLength = ntohs(dcpHeader.dataLength);
    dcpHeader.responseDelay = ntohs(dcpHeader.responseDelay);

    struct profinet_packet profinetPacket;
    profinetPacket.dcpHeader = dcpHeader;
    memcpy(profinetPacket.dataBlock, profinetPacketRaw + sizeof(dcpHeader), dcpHeader.dataLength);
    memcpy(profinetPacket.sourceMACAddress, header.ether_shost, sizeof(header.ether_shost));

    struct profinet_packet_array *profinetPacketArray = (struct profinet_packet_array *) args;

    profinetPacketArray->packets[count] = profinetPacket;
    profinetPacketArray->size++;

    count++;
}

void get_default_interface(char *interface) {
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_errbuf[0] = '\0';
    pcap_if_t *interfaces;
    if (pcap_findalldevs(&interfaces, pcap_errbuf) == 0)
        strcpy(interface, interfaces->name);
}

void discovery_request(const char interface[]) {
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_errbuf[0] = '\0';
    pcap_t *pcap = pcap_open_live(interface, BUFSIZ, 0, 0, pcap_errbuf);
    if (pcap_errbuf[0] != '\0') {
        fprintf(stderr, "%s", pcap_errbuf);
    }
    if (!pcap) {
        exit(1);
    }

    struct ether_header header;
    header.ether_type = htons(ETH_P_8021Q);

    uint8_t hostMac[6];
    getInterfaceMACAddress(interface, hostMac);
    memcpy(header.ether_shost, hostMac, sizeof(hostMac));

    uint8_t destMac[6] = DEST_MAC_MULTICAST;
    memcpy(header.ether_dhost, destMac, sizeof(destMac));

    uint8_t vlan_header[4] = VLAN_HEADER;

    uint8_t blockData[4] = DCP_BLOCK_IDENTIFY_SELECT_ALL;
    struct profinet_dcp_header profinet_header = {
            .frameId = 0xfefe,
            .serviceId = 5,
            .serviceType = 0,
            .transactionId = htonl(1),
            .responseDelay = htons(1),
            .dataLength = htons(sizeof(blockData)),
    };

    unsigned char request[sizeof(header) + sizeof(vlan_header) + sizeof(profinet_header) + sizeof(blockData)];
    memcpy(request, &header, sizeof(header));
    memcpy(request + sizeof(header), &vlan_header, sizeof(vlan_header));
    memcpy(request + sizeof(header) + sizeof(vlan_header), &profinet_header, sizeof(profinet_header));
    memcpy(request + sizeof(header) + sizeof(vlan_header) + sizeof(profinet_header), blockData, sizeof(blockData));

    if (pcap_inject(pcap, &request, sizeof(request)) == -1) {
        pcap_perror(pcap, 0);
        pcap_close(pcap);
        exit(1);
    }

    pcap_close(pcap);
}


void profinet_listen(const char interface[], struct profinet_packet_array *profinetPacketArray, int timeout) {
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_errbuf[0] = '\0';

    pcap_t *pcap = pcap_open_live(interface, BUFSIZ, 1, 1000, pcap_errbuf);
    if (pcap_errbuf[0] != '\0') {
        fprintf(stderr, "%s", pcap_errbuf);
    }
    if (!pcap) {
        exit(1);
    }

    time_t start = time(NULL);
    time_t end = start + (timeout / 1000);

    while(time(NULL) < end){
        pcap_dispatch(pcap, 0, &profinetCallback, (unsigned char *) profinetPacketArray);
    }

    pcap_close(pcap);
}

void get_profinet_devices(struct profinet_packet_array *profinetPacketArray, struct profinet_device *profinetDevices,
                          int *count) {
    struct profinet_device deviceList[PROFINET_DEVICE_LIST_SIZE];
    int deviceCount = 0;

    for (int i = 0; i < profinetPacketArray->size; ++i) {
        struct profinet_packet packet = profinetPacketArray->packets[i];
        if (packet.dcpHeader.serviceId == 5 && packet.dcpHeader.serviceType == 1) {
            struct profinet_device device = getIdentifyResponse(packet.dataBlock,
                                                                packet.dcpHeader.dataLength);
            memcpy(device.macAddress, packet.sourceMACAddress, sizeof(device.macAddress));
            memcpy(&deviceList[deviceCount], &device, sizeof(device));
            //deviceList[i] = device;
            deviceCount++;
        }
    }

    memcpy(profinetDevices, deviceList, sizeof(deviceList));
    *count = deviceCount;
}

void set_device_ip_block(const char interface[], struct profinet_device *device){
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_errbuf[0] = '\0';
    pcap_t *pcap = pcap_open_live(interface, BUFSIZ, 0, 0, pcap_errbuf);
    if (pcap_errbuf[0] != '\0') {
        fprintf(stderr, "%s", pcap_errbuf);
    }
    if (!pcap) {
        exit(1);
    }

    struct ether_header header;
    header.ether_type = htons(ETH_P_8021Q);

    uint8_t hostMac[6];
    getInterfaceMACAddress(interface, hostMac);
    memcpy(header.ether_shost, hostMac, sizeof(hostMac));

    memcpy(header.ether_dhost, device->macAddress, sizeof(device->macAddress));

    uint8_t vlan_header[4] = VLAN_HEADER;

    struct profinet_dcp_block_ip_s ipBlock;
    ipBlock.option = 1;
    ipBlock.suboption = 2;
    ipBlock.length = htons(14);
    ipBlock.qualifier = 0;
    memcpy(&ipBlock.ip_address, &device->ipAddress, sizeof(ipBlock.ip_address));
    memcpy(&ipBlock.subnet_mask, &device->subnetMask, sizeof(ipBlock.subnet_mask));
    memcpy(&ipBlock.standard_gateway, &device->gateway, sizeof(ipBlock.standard_gateway));

    uint8_t endBlock[6] = DCP_BLOCK_CONTROL_END_TRANSACTION;

    uint8_t blockData[ sizeof(ipBlock) + sizeof(endBlock) ];
    memcpy(blockData, &ipBlock, sizeof(ipBlock));
    memcpy(blockData + sizeof(ipBlock), endBlock, sizeof(endBlock));

    struct profinet_dcp_header profinet_header = {
            .frameId = htons(0xfefd),
            .serviceId = 4,
            .serviceType = 0,
            .transactionId = htonl(2),
            .responseDelay = htons(0),
            .dataLength = htons(sizeof(blockData)),
    };

    unsigned char request[sizeof(header) + sizeof(vlan_header) + sizeof(profinet_header) + sizeof(blockData)];
    memcpy(request, &header, sizeof(header));
    memcpy(request + sizeof(header), &vlan_header, sizeof(vlan_header));
    memcpy(request + sizeof(header) + sizeof(vlan_header), &profinet_header, sizeof(profinet_header));
    memcpy(request + sizeof(header) + sizeof(vlan_header) + sizeof(profinet_header), blockData, sizeof(blockData));

    int injectRet = pcap_inject(pcap, request, sizeof(request));
    if (injectRet == -1) {
        pcap_perror(pcap, 0);
        pcap_close(pcap);
        exit(1);
    }

    pcap_close(pcap);
}

void set_device_name_block(const char interface[], struct profinet_device *device) {
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_errbuf[0] = '\0';
    pcap_t *pcap = pcap_open_live(interface, BUFSIZ, 0, 0, pcap_errbuf);
    if (pcap_errbuf[0] != '\0') {
        fprintf(stderr, "%s", pcap_errbuf);
    }
    if (!pcap) {
        exit(1);
    }

    struct ether_header header;
    header.ether_type = htons(ETH_P_8021Q);

    uint8_t hostMac[6];
    getInterfaceMACAddress(interface, hostMac);
    memcpy(header.ether_shost, hostMac, sizeof(hostMac));

    memcpy(header.ether_dhost, device->macAddress, sizeof(device->macAddress));

    uint8_t vlan_header[4] = VLAN_HEADER;

    size_t sizeToPad;
    if(strlen(device->deviceName) % 2 == 0) sizeToPad = 0;
    else sizeToPad = 1;

    uint8_t nameBlock[6 + strlen(device->deviceName) + sizeToPad];
    uint8_t namePreBlock[6] = {
            2,
            2
    };
    uint16_t nameBlockLength = htons(strlen(device->deviceName) + 2);
    memcpy(namePreBlock + 2, &nameBlockLength, 2);
    memset(namePreBlock + 4, 0x0000, 1);
    memcpy(nameBlock, namePreBlock, 6);
    memcpy(nameBlock + 6, device->deviceName, strlen(device->deviceName));
    memset(nameBlock + 6 + strlen(device->deviceName), 0, 1);

    uint8_t endBlock[6] = DCP_BLOCK_CONTROL_END_TRANSACTION;

    uint8_t blockData[ sizeof(nameBlock) + sizeof(endBlock) ];
    memcpy(blockData, nameBlock, sizeof(nameBlock));
    memcpy(blockData + sizeof(nameBlock), endBlock, sizeof(endBlock));

    struct profinet_dcp_header profinet_header = {
            .frameId = htons(0xfefd),
            .serviceId = 4,
            .serviceType = 0,
            .transactionId = htonl(2),
            .responseDelay = htons(0),
            .dataLength = htons(sizeof(blockData)),
    };

    unsigned char request[sizeof(header) + sizeof(vlan_header) + sizeof(profinet_header) + sizeof(blockData)];
    memcpy(request, &header, sizeof(header));
    memcpy(request + sizeof(header), &vlan_header, sizeof(vlan_header));
    memcpy(request + sizeof(header) + sizeof(vlan_header), &profinet_header, sizeof(profinet_header));
    memcpy(request + sizeof(header) + sizeof(vlan_header) + sizeof(profinet_header), blockData, sizeof(blockData));

    int injectRet = pcap_inject(pcap, request, sizeof(request));
    if (injectRet == -1) {
        pcap_perror(pcap, 0);
        pcap_close(pcap);
        exit(1);
    }

    pcap_close(pcap);
}

void set_device_configuration(const char *interface, struct profinet_device *device) {
    set_device_ip_block(interface, device);
    set_device_name_block(interface, device);
}
