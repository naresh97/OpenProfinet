#include "ProfinetTool.h"

int main() {
    ProfinetTool profinetTool("enp9s0");
    profinetTool.searchForDevices();
    return 0;
}
