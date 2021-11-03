//
// Created by naresh on 30/10/2021.
//

#ifndef OPENPROFINET_PCAPINTERFACE_H
#define OPENPROFINET_PCAPINTERFACE_H

/**
 * Defines buffer size for number of Profinet devices on the network
 */
#define PROFINET_DEVICE_LIST_SIZE 32

#include <pcap/pcap.h>
#include <stdlib.h>
#include <stdbool.h>
#include "profinetTypes.h"

/**
 * Gets the default network interface on the machine
 * @param interface Pointer of char array to output interface
 */
void get_default_interface(char *interface);

/**
 * Create a multicast Profinet-DCP discovery request. Profinet devices on the network will respond
 * to this request.
 * @param interface Interface to broadcast request on
 */
void discovery_request(const char interface[]);

/**
 * Listen for Profinet packets
 * @param interface Interface to listen on
 * @param profinetPacketArray Pointer to array of Profinet packets to output to
 * @param timeout Listen timeout in seconds
 */
void profinet_listen(const char interface[], struct profinet_packet_array *profinetPacketArray, int timeout);

/**
 * Gets discovery responses from a provided array of Profinet packets
 * @param profinetPacketArray Pointer to array of packets to search
 * @param profinetDevices Pointer to array of Profinet devices to output to
 * @param count Pointer to integer of number of Profinet devices found to output to
 */
void get_profinet_devices(struct profinet_packet_array *profinetPacketArray, struct profinet_device *profinetDevices,
                          int *count);

/**
 * Sends a request to a device, requesting it to configure itself to the given parameters
 * @param interface Interface, over which to send configuration request
 * @param device Pointer to the Profinet device to send request to
 * @return Whether the device has acknowledged the configuration request
 */
bool set_device_configuration(const char *interface, struct profinet_device *device);

#endif //OPENPROFINET_PCAPINTERFACE_H
