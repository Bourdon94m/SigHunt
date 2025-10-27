#include "SigHunt.h"
#include <chrono>



int main()
{
    auto start = std::chrono::high_resolution_clock::now();

    
    uintptr_t addr = SigHunt::External::Find("FiveM_b3407_GameProcess.exe",
        "48 8D 0D B0 42 E9 01 41 B6 01 44 89 2D");

    auto end = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    std::cout << "Found at: 0x" << std::hex << addr << std::endl;
    std::cout << "Scan time: " << std::dec << ms.count() << "ms\n";

    return 0;
}
