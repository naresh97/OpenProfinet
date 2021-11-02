# OpenProfinet

A collection of tools for configuring Profinet devices on Linux based systems.
Uses libpcap library for creating Ethernet frames.

## Usage: pntool

### pntool search
```
Search for Profinet devices on the network.
Usage: pntool search [OPTIONS]

Options:
  -h,--help                   Print this help message and exit
  -i,--interface              Interface to use
  -t,--timeout INT            Time to search for devices in milliseconds

```

### pntool configure
```
Configure Profinet devices on the network.
Usage: pntool configure [OPTIONS] device

Positionals:
  device REQUIRED             The current name of the device to configure

Options:
  -h,--help                   Print this help message and exit
  -t,--timeout INT            Time to search for devices in milliseconds
  -n,--name TEXT              Set a new name for the device
  -i,--ip TEXT                New IP Address
  -s,--subnet TEXT            New Subnet Mask
  -g,--gateway TEXT           New Gateway Address

```

## Building

Uses CMake as build system.

```bash
mkdir ./build
cd ./build
cmake ..
make
```

## Licensing

This software is open-source and free to use as specified in the GPLv3 license for **non-commercial** use only.
Permission for commercial use require explicit permission of the author.