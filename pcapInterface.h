//
// Created by naresh on 30/10/2021.
//

#ifndef OPENPROFINET_PCAPINTERFACE_H
#define OPENPROFINET_PCAPINTERFACE_H

#define PROFINET_DEVICE_LIST_SIZE 32

#include <pcap/pcap.h>
#include <stdlib.h>
#include <slcurses.h>
#include "profinetTypes.h"

void discoveryRequest(const char interface[]);

void profinetListen(const char interface[], struct profinet_packet_array *profinetPacketArray);

void getProfinetDevices(struct profinet_packet_array *profinetPacketArray, struct profinet_device *profinetDevices,
                        int *count);

#endif //OPENPROFINET_PCAPINTERFACE_H
