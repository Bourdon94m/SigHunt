#include "SigHunt.h"
#include <chrono>



int main()
{
    auto start = std::chrono::high_resolution_clock::now();

    // Simple example here
    uintptr_t addr = SigHunt::External::Find("CalculatorApp.exe",
        "E8 C3 ?? ?? ?? ?? ?? 90");

    uintptr_t addr2 = SigHunt::Internal::Find("E8 C3 ?? ?? ?? ?? ?? 90");


    std::vector<uintptr_t> allResExternal = SigHunt::External::FindAll("CalculatorApp.exe", "E8 C3 ?? ?? ?? ?? ?? 90");
    std::vector<uintptr_t> allResInternal = SigHunt::Internal::FindAll("E8 C3 ?? ?? ?? ?? ?? 90");



    auto end = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    std::cout << "Found at: 0x" << std::hex << addr << std::endl;
    std::cout << "Scan time: " << std::dec << ms.count() << "ms\n";

    return 0;
}
