#include "ProfinetTool.h"
#include <CLI11.hpp>

int main(int argc, char **argv) {

    CLI::App app{"pntool is part of the OpenProfinet project. It is used to configure Profinet networks."};
    app.require_subcommand();

    CLI::App *search = app.add_subcommand("search", "Search for Profinet devices on the network.");
    CLI::Option *interface = search->add_option("-i,--interface", "Interface to use");
    int timeout = 1000;
    search->add_option("-t,--timeout", timeout, "Time to search for devices in milliseconds");

    CLI::App *configure = app.add_subcommand("configure", "Configure Profinet devices on the network.");
    CLI::Option *device = configure->add_option("device", "The current name of the device to configure")
            ->required(true);
    configure->add_option("-t,--timeout", timeout, "Time to search for devices in milliseconds");

    std::string newName;
    configure->add_option("-n,--name", newName, "Set a new name for the device");

    std::string newIP;
    configure->add_option("-i,--ip", newIP, "New IP Address");
    std::string newSubnet;
    configure->add_option("-s,--subnet", newSubnet, "New Subnet Mask");
    std::string newGateway;
    configure->add_option("-g,--gateway", newGateway, "New Gateway Address");

    CLI11_PARSE(app, argc, argv);

    try {
        if (*search) {
            ProfinetTool profinetTool(timeout);
            if (!interface->empty()) profinetTool = ProfinetTool(interface->as<std::string>(), timeout);
            profinetTool.searchForDevices();
        } else if (*configure) {
            ProfinetTool profinetTool(timeout);
            profinetTool.configureDevices(device->as<std::string>(), newName, newIP, newSubnet,
                                          newGateway);
        }
    } catch (const std::runtime_error &e) {
        std::cerr << "Could not run command: " << e.what() << std::endl;
    }


    return 0;
}
