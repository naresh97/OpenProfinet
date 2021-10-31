#include "ProfinetTool.h"
#include <CLI11.hpp>

int main(int argc, char **argv) {

    CLI::App app{"pntool is part of the OpenProfinet project. It is used to configure Profinet networks."};

    CLI::App *search = app.add_subcommand("search", "Search for Profinet devices on the network.");
    app.require_subcommand();
    CLI::Option *interface = search->add_option("-i,--interface", "Interface to use");
    int timeout = 2000;
    search->add_option("-t,--timeout", timeout, "Time to search for devices in milliseconds");

    CLI11_PARSE(app, argc, argv);

    if(*search){
        ProfinetTool profinetTool(timeout);
        if(!interface->empty()) profinetTool = ProfinetTool(interface->as<std::string>(), timeout);
        profinetTool.searchForDevices();
    }

    return 0;
}
