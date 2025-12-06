#include "SigHunt.h"
#include <chrono>

int main()
{
    auto start = std::chrono::high_resolution_clock::now();

    // External scanning
    uintptr_t addr = SigHunt::External::Find("CalculatorApp.exe",
        "E8 C3 ?? ?? ?? ?? ?? 90");

    // Internal scanning
    uintptr_t addr2 = SigHunt::Internal::Find("E8 C3 ?? ?? ?? ?? ?? 90");

    // Find all external matches
    std::vector<uintptr_t> allResExternal = SigHunt::External::FindAll("CalculatorApp.exe",
        "E8 C3 ?? ?? ?? ?? ?? 90");

    // Find all internal matches
    std::vector<uintptr_t> allResInternal = SigHunt::Internal::FindAll("E8 C3 ?? ?? ?? ?? ?? 90");

    // VTable instances from first match
    std::vector<uintptr_t> vtableInstances = SigHunt::VTableScanner::FindVTableInstances(addr);

    auto end = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    std::cout << "External: 0x" << std::hex << addr << std::endl;
    std::cout << "Internal: 0x" << std::hex << addr2 << std::endl;
    std::cout << "All External matches: " << std::dec << allResExternal.size() << std::endl;
    std::cout << "All Internal matches: " << std::dec << allResInternal.size() << std::endl;
    std::cout << "VTable instances: " << std::dec << vtableInstances.size() << std::endl;
    std::cout << "Total scan time: " << std::dec << ms.count() << "ms\n";

    return 0;
}