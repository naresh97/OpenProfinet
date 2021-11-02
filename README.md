# OpenProfinet

A collection of tools for configuring Profinet devices on Linux based systems.
Uses libpcap library for creating Ethernet frames.

## Usage

```
Search for Profinet devices on the network.
Usage: pntool search [OPTIONS]

Options:
  -h,--help                   Print this help message and exit
  -i,--interface              Interface to use
  -t,--timeout INT            Time to search for devices in milliseconds

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

This software is open-source and free to use as specified in the GPLv3 license. However, commercial use of this software is only allowed with explicit permission from the author.
