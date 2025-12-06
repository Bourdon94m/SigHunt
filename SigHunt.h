#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <string>
#include <vector>
#include <iostream>
#include <thread>
#include <mutex>
#include <algorithm>
#include <immintrin.h> // SSE/AVX intrinsics

// Pattern: bytes vector + mask string (e.g., "xx?x" where ? = wildcard)
using Pattern = std::pair<std::vector<uint8_t>, std::string>;

// Module address range: [base, end]
using AddressRange = std::pair<uintptr_t, uintptr_t>;

namespace SigHunt
{
    // ============================================================================
    // HELPER FUNCTIONS
    // ============================================================================
    namespace Detail
    {
        // Convert std::string to std::wstring
        inline std::wstring StringToWide(const std::string& str)
        {
            if (str.empty()) return std::wstring();

            int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
            std::wstring result(size, 0);
            MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &result[0], size);
            return result;
        }

        // Get process ID by name (case-insensitive)
        inline DWORD GetProcessID(const std::wstring& processName)
        {
            DWORD procID = 0;
            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

            if (snapshot == INVALID_HANDLE_VALUE)
            {
                std::cerr << "[ERROR] Failed to create process snapshot\n";
                return 0;
            }

            PROCESSENTRY32W entry = {};
            entry.dwSize = sizeof(PROCESSENTRY32W);

            if (Process32FirstW(snapshot, &entry))
            {
                do
                {
                    if (_wcsicmp(processName.c_str(), entry.szExeFile) == 0)
                    {
                        procID = entry.th32ProcessID;
                        break;
                    }
                } while (Process32NextW(snapshot, &entry));
            }

            CloseHandle(snapshot);
            return procID;
        }

        // Parse pattern string like "E8 ?? C3 48" into bytes + mask
        inline Pattern ParsePattern(const std::string& patternStr)
        {
            Pattern result;
            std::vector<uint8_t>& bytes = result.first;
            std::string& mask = result.second;

            // Remove all spaces
            std::string cleaned;
            cleaned.reserve(patternStr.size());
            for (char c : patternStr)
            {
                if (c != ' ') cleaned += c;
            }

            if (cleaned.empty() || cleaned.size() % 2 != 0)
            {
                std::cerr << "[ERROR] Invalid pattern format\n";
                return Pattern{};
            }

            // Pre-allocate for performance
            size_t patternSize = cleaned.size() / 2;
            bytes.reserve(patternSize);
            mask.reserve(patternSize);

            // Parse pairs of hex digits
            for (size_t i = 0; i < cleaned.size(); i += 2)
            {
                char a = cleaned[i];
                char b = cleaned[i + 1];

                // Wildcard check
                if (a == '?' || b == '?')
                {
                    bytes.push_back(0x00);
                    mask.push_back('?');
                    continue;
                }

                // Validate and convert hex digits
                if (!isxdigit(static_cast<unsigned char>(a)) ||
                    !isxdigit(static_cast<unsigned char>(b)))
                {
                    std::cerr << "[ERROR] Invalid hex pair: " << a << b << "\n";
                    return Pattern{};
                }

                // Fast hex conversion
                unsigned int value = 0;
                std::string hexPair = cleaned.substr(i, 2);

                try
                {
                    value = std::stoul(hexPair, nullptr, 16);
                }
                catch (...)
                {
                    std::cerr << "[ERROR] Failed to parse hex: " << hexPair << "\n";
                    return Pattern{};
                }

                bytes.push_back(static_cast<uint8_t>(value));
                mask.push_back('x');
            }

            return result;
        }

        // Get module address range for current process
        inline AddressRange GetModuleRange(const std::string& moduleName)
        {
            AddressRange result = { 0, 0 };

            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                GetCurrentProcessId());

            if (snapshot == INVALID_HANDLE_VALUE)
            {
                std::cerr << "[ERROR] Failed to create module snapshot\n";
                return result;
            }

            MODULEENTRY32W entry = {};
            entry.dwSize = sizeof(MODULEENTRY32W);

            std::wstring wideModName = StringToWide(moduleName);

            if (Module32FirstW(snapshot, &entry))
            {
                do
                {
                    if (_wcsicmp(wideModName.c_str(), entry.szModule) == 0)
                    {
                        result.first = reinterpret_cast<uintptr_t>(entry.modBaseAddr);
                        result.second = result.first + entry.modBaseSize;
                        break;
                    }
                } while (Module32NextW(snapshot, &entry));
            }

            CloseHandle(snapshot);
            return result;
        }

        // Check if memory protection allows reading
        inline bool IsReadableProtection(DWORD protect)
        {
            return (protect & PAGE_READONLY) ||
                (protect & PAGE_READWRITE) ||
                (protect & PAGE_EXECUTE_READ) ||
                (protect & PAGE_EXECUTE_READWRITE);
        }

        // ========================================================================
        // OPTIMIZED PATTERN COMPARISON WITH SIMD (SSE2)
        // ========================================================================
        // This function uses SIMD instructions to compare 16 bytes at once
        // Falls back to regular comparison for patterns < 16 bytes or remainder
        inline bool ComparePatternFast(const uint8_t* data, size_t dataSize, size_t offset,
            const std::vector<uint8_t>& patternBytes,
            const std::string& patternMask)
        {
            size_t patSize = patternBytes.size();

            if (offset + patSize > dataSize)
                return false;

            const uint8_t* scanData = data + offset;

            // For small patterns, use regular comparison (faster than SIMD overhead)
            if (patSize < 16)
            {
                for (size_t i = 0; i < patSize; ++i)
                {
                    if (patternMask[i] == '?')
                        continue;

                    if (scanData[i] != patternBytes[i])
                        return false;
                }
                return true;
            }

            // SIMD comparison for patterns >= 16 bytes
            size_t i = 0;

            // Process 16 bytes at a time using SSE2
            for (; i + 16 <= patSize; i += 16)
            {
                // Check if any wildcards in this chunk
                bool hasWildcard = false;
                for (size_t j = i; j < i + 16; ++j)
                {
                    if (patternMask[j] == '?')
                    {
                        hasWildcard = true;
                        break;
                    }
                }

                // If wildcards present, fall back to byte-by-byte
                if (hasWildcard)
                {
                    for (size_t j = i; j < i + 16; ++j)
                    {
                        if (patternMask[j] == '?')
                            continue;

                        if (scanData[j] != patternBytes[j])
                            return false;
                    }
                }
                else
                {
                    // No wildcards: use SIMD for 16-byte comparison
                    __m128i data_chunk = _mm_loadu_si128(reinterpret_cast<const __m128i*>(scanData + i));
                    __m128i pattern_chunk = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&patternBytes[i]));

                    __m128i cmp = _mm_cmpeq_epi8(data_chunk, pattern_chunk);
                    int mask = _mm_movemask_epi8(cmp);

                    // If all 16 bytes match, mask will be 0xFFFF
                    if (mask != 0xFFFF)
                        return false;
                }
            }

            // Handle remaining bytes
            for (; i < patSize; ++i)
            {
                if (patternMask[i] == '?')
                    continue;

                if (scanData[i] != patternBytes[i])
                    return false;
            }

            return true;
        }

        // RAII wrapper for HANDLE to prevent leaks
        class HandleGuard
        {
        public:
            explicit HandleGuard(HANDLE h) : handle(h) {}
            ~HandleGuard() { if (handle && handle != INVALID_HANDLE_VALUE) CloseHandle(handle); }

            operator HANDLE() const { return handle; }
            HANDLE get() const { return handle; }
            bool valid() const { return handle && handle != INVALID_HANDLE_VALUE; }

        private:
            HANDLE handle;
            HandleGuard(const HandleGuard&) = delete;
            HandleGuard& operator=(const HandleGuard&) = delete;
        };

        // ========================================================================
        // MULTI-THREADED SCAN HELPER
        // ========================================================================
        struct ScanRegion
        {
            uintptr_t start;
            uintptr_t end;
        };

        // Divide memory into chunks for parallel scanning
        inline std::vector<ScanRegion> DivideIntoRegions(uintptr_t startAddr, uintptr_t endAddr, size_t numThreads)
        {
            std::vector<ScanRegion> regions;
            uintptr_t totalSize = endAddr - startAddr;
            uintptr_t chunkSize = totalSize / numThreads;

            for (size_t i = 0; i < numThreads; ++i)
            {
                ScanRegion region;
                region.start = startAddr + (i * chunkSize);
                region.end = (i == numThreads - 1) ? endAddr : region.start + chunkSize;
                regions.push_back(region);
            }

            return regions;
        }
    }

    // ============================================================================
    // EXTERNAL SCANNING (Remote Process) - MULTI-THREADED
    // ============================================================================
    namespace External
    {
        // Worker thread function for parallel external scanning
        inline void ScanWorker(HANDLE hProcess, uintptr_t startAddr, uintptr_t endAddr,
            const std::vector<uint8_t>& patternBytes,
            const std::string& patternMask,
            std::vector<uintptr_t>& results,
            std::mutex& resultMutex,
            bool findFirst,
            std::atomic<bool>& found)
        {
            size_t patSize = patternBytes.size();
            const SIZE_T MAX_REGION_SIZE = 0x10000000; // 256 MB
            uintptr_t currentAddr = startAddr;

            while (currentAddr < endAddr && (!findFirst || !found.load()))
            {
                MEMORY_BASIC_INFORMATION mbi = {};

                if (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(currentAddr),
                    &mbi, sizeof(mbi)) == 0)
                {
                    currentAddr += 0x1000;
                    continue;
                }

                if (reinterpret_cast<uintptr_t>(mbi.BaseAddress) >= endAddr)
                    break;

                if ((mbi.State == MEM_COMMIT) && Detail::IsReadableProtection(mbi.Protect))
                {
                    SIZE_T regionSize = mbi.RegionSize;

                    // Don't scan past our assigned region
                    uintptr_t regionEnd = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + regionSize;
                    if (regionEnd > endAddr)
                        regionSize = endAddr - reinterpret_cast<uintptr_t>(mbi.BaseAddress);

                    if (regionSize > MAX_REGION_SIZE)
                        regionSize = MAX_REGION_SIZE;

                    std::vector<uint8_t> buffer(regionSize);
                    SIZE_T bytesRead = 0;

                    if (ReadProcessMemory(hProcess, mbi.BaseAddress,
                        buffer.data(), regionSize, &bytesRead))
                    {
                        if (bytesRead >= patSize)
                        {
                            for (size_t offset = 0; offset <= bytesRead - patSize; ++offset)
                            {
                                if (Detail::ComparePatternFast(buffer.data(), bytesRead, offset,
                                    patternBytes, patternMask))
                                {
                                    uintptr_t foundAddr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + offset;

                                    std::lock_guard<std::mutex> lock(resultMutex);
                                    results.push_back(foundAddr);

                                    if (findFirst)
                                    {
                                        found.store(true);
                                        return;
                                    }
                                }
                            }
                        }
                    }
                }

                currentAddr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            }
        }

        // Find first pattern match (multi-threaded)
        inline uintptr_t Find(const std::string& processName, const std::string& patternStr)
        {
            auto [patternBytes, patternMask] = Detail::ParsePattern(patternStr);
            size_t patSize = patternBytes.size();

            if (patSize == 0)
            {
                std::cerr << "[ERROR] Invalid pattern\n";
                return 0;
            }

            std::wstring wideProcessName = Detail::StringToWide(processName);
            DWORD procID = Detail::GetProcessID(wideProcessName);

            if (procID == 0)
            {
                std::cerr << "[ERROR] Process not found: " << processName << "\n";
                return 0;
            }

            Detail::HandleGuard hProcess(OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                FALSE, procID));

            if (!hProcess.valid())
            {
                std::cerr << "[ERROR] Failed to open process (ID: " << procID << ")\n";
                return 0;
            }

            // Use multiple threads for faster scanning
            unsigned int numThreads = std::thread::hardware_concurrency();
            if (numThreads == 0) numThreads = 4;

            uintptr_t startAddr = 0x10000;
            uintptr_t endAddr = 0x00007FFFFFFFFFFF;

            auto regions = Detail::DivideIntoRegions(startAddr, endAddr, numThreads);

            std::vector<uintptr_t> results;
            std::mutex resultMutex;
            std::atomic<bool> found(false);
            std::vector<std::thread> threads;

            for (const auto& region : regions)
            {
                threads.emplace_back(ScanWorker, hProcess.get(), region.start, region.end,
                    std::ref(patternBytes), std::ref(patternMask),
                    std::ref(results), std::ref(resultMutex), true, std::ref(found));
            }

            for (auto& thread : threads)
                thread.join();

            if (!results.empty())
            {
                // Return the lowest address found
                return *std::min_element(results.begin(), results.end());
            }

            return 0;
        }

        // Find all pattern matches (multi-threaded)
        inline std::vector<uintptr_t> FindAll(const std::string& processName,
            const std::string& patternStr)
        {
            std::vector<uintptr_t> results;

            auto [patternBytes, patternMask] = Detail::ParsePattern(patternStr);
            size_t patSize = patternBytes.size();

            if (patSize == 0)
            {
                std::cerr << "[ERROR] Invalid pattern\n";
                return results;
            }

            std::wstring wideProcessName = Detail::StringToWide(processName);
            DWORD procID = Detail::GetProcessID(wideProcessName);

            if (procID == 0)
            {
                std::cerr << "[ERROR] Process not found: " << processName << "\n";
                return results;
            }

            Detail::HandleGuard hProcess(OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                FALSE, procID));

            if (!hProcess.valid())
            {
                std::cerr << "[ERROR] Failed to open process (ID: " << procID << ")\n";
                return results;
            }

            unsigned int numThreads = std::thread::hardware_concurrency();
            if (numThreads == 0) numThreads = 4;

            uintptr_t startAddr = 0x10000;
            uintptr_t endAddr = 0x00007FFFFFFFFFFF;

            auto regions = Detail::DivideIntoRegions(startAddr, endAddr, numThreads);

            std::mutex resultMutex;
            std::atomic<bool> found(false);
            std::vector<std::thread> threads;

            for (const auto& region : regions)
            {
                threads.emplace_back(ScanWorker, hProcess.get(), region.start, region.end,
                    std::ref(patternBytes), std::ref(patternMask),
                    std::ref(results), std::ref(resultMutex), false, std::ref(found));
            }

            for (auto& thread : threads)
                thread.join();

            // Sort results by address
            std::sort(results.begin(), results.end());

            return results;
        }
    }

    // ============================================================================
    // INTERNAL SCANNING (Current Process) - OPTIMIZED
    // ============================================================================
    namespace Internal
    {
        // Find first pattern match in current process (SIMD optimized)
        inline uintptr_t Find(const std::string& patternStr)
        {
            auto [patternBytes, patternMask] = Detail::ParsePattern(patternStr);
            size_t patSize = patternBytes.size();

            if (patSize == 0)
            {
                std::cerr << "[ERROR] Invalid pattern\n";
                return 0;
            }

            uintptr_t currentAddr = 0x10000;
            const uintptr_t maxAddr = 0x00007FFFFFFFFFFF;
            const SIZE_T MAX_REGION_SIZE = 0x10000000;

            while (currentAddr < maxAddr)
            {
                MEMORY_BASIC_INFORMATION mbi = {};

                if (VirtualQuery(reinterpret_cast<LPCVOID>(currentAddr), &mbi, sizeof(mbi)) == 0)
                {
                    currentAddr += 0x1000;
                    continue;
                }

                if ((mbi.State == MEM_COMMIT) && Detail::IsReadableProtection(mbi.Protect))
                {
                    SIZE_T regionSize = mbi.RegionSize;
                    if (regionSize > MAX_REGION_SIZE)
                        regionSize = MAX_REGION_SIZE;

                    const uint8_t* data = static_cast<const uint8_t*>(mbi.BaseAddress);

                    // Use SIMD-optimized comparison
                    for (size_t offset = 0; offset <= regionSize - patSize; ++offset)
                    {
                        if (Detail::ComparePatternFast(data, regionSize, offset,
                            patternBytes, patternMask))
                        {
                            return reinterpret_cast<uintptr_t>(data) + offset;
                        }
                    }
                }

                currentAddr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            }

            return 0;
        }

        // Find in module (SIMD optimized)
        inline uintptr_t FindInModule(const std::string& moduleName,
            const std::string& patternStr)
        {
            auto [patternBytes, patternMask] = Detail::ParsePattern(patternStr);
            size_t patSize = patternBytes.size();

            if (patSize == 0)
            {
                std::cerr << "[ERROR] Invalid pattern\n";
                return 0;
            }

            auto [baseAddr, endAddr] = Detail::GetModuleRange(moduleName);

            if (baseAddr == 0 || endAddr == 0)
            {
                std::cerr << "[ERROR] Module not found: " << moduleName << "\n";
                return 0;
            }

            uintptr_t currentAddr = baseAddr;
            const SIZE_T MAX_REGION_SIZE = 0x10000000;

            while (currentAddr < endAddr)
            {
                MEMORY_BASIC_INFORMATION mbi = {};

                if (VirtualQuery(reinterpret_cast<LPCVOID>(currentAddr), &mbi, sizeof(mbi)) == 0)
                {
                    currentAddr += 0x1000;
                    continue;
                }

                if ((mbi.State == MEM_COMMIT) && Detail::IsReadableProtection(mbi.Protect))
                {
                    SIZE_T regionSize = mbi.RegionSize;

                    uintptr_t regionEnd = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + regionSize;
                    if (regionEnd > endAddr)
                        regionSize = endAddr - reinterpret_cast<uintptr_t>(mbi.BaseAddress);

                    if (regionSize > MAX_REGION_SIZE)
                        regionSize = MAX_REGION_SIZE;

                    const uint8_t* data = static_cast<const uint8_t*>(mbi.BaseAddress);

                    for (size_t offset = 0; offset <= regionSize - patSize; ++offset)
                    {
                        if (Detail::ComparePatternFast(data, regionSize, offset,
                            patternBytes, patternMask))
                        {
                            return reinterpret_cast<uintptr_t>(data) + offset;
                        }
                    }
                }

                currentAddr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            }

            return 0;
        }

        // Find all matches (SIMD optimized)
        inline std::vector<uintptr_t> FindAll(const std::string& patternStr)
        {
            std::vector<uintptr_t> results;

            auto [patternBytes, patternMask] = Detail::ParsePattern(patternStr);
            size_t patSize = patternBytes.size();

            if (patSize == 0)
            {
                std::cerr << "[ERROR] Invalid pattern\n";
                return results;
            }

            uintptr_t currentAddr = 0x10000;
            const uintptr_t maxAddr = 0x00007FFFFFFFFFFF;
            const SIZE_T MAX_REGION_SIZE = 0x10000000;

            while (currentAddr < maxAddr)
            {
                MEMORY_BASIC_INFORMATION mbi = {};

                if (VirtualQuery(reinterpret_cast<LPCVOID>(currentAddr), &mbi, sizeof(mbi)) == 0)
                {
                    currentAddr += 0x1000;
                    continue;
                }

                if ((mbi.State == MEM_COMMIT) && Detail::IsReadableProtection(mbi.Protect))
                {
                    SIZE_T regionSize = mbi.RegionSize;
                    if (regionSize > MAX_REGION_SIZE)
                        regionSize = MAX_REGION_SIZE;

                    const uint8_t* data = static_cast<const uint8_t*>(mbi.BaseAddress);

                    for (size_t offset = 0; offset <= regionSize - patSize; ++offset)
                    {
                        if (Detail::ComparePatternFast(data, regionSize, offset,
                            patternBytes, patternMask))
                        {
                            results.push_back(reinterpret_cast<uintptr_t>(data) + offset);
                        }
                    }
                }

                currentAddr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            }

            return results;
        }
    }


    // ========================================================================
    // VTABLE INSTANCE SCANNING
    // ========================================================================
    namespace VTableScanner
    {
        

        // Find all instances of a vtable in the current process
        inline std::vector<uintptr_t> FindVTableInstances(uintptr_t vtableAddr)
        {
            std::vector<uintptr_t> results;

            if (vtableAddr == 0)
            {
                std::cerr << "[ERROR] Invalid vtable address\n";
                return results;
            }

            uintptr_t currentAddr = 0x10000;
            const uintptr_t maxAddr = 0x00007FFFFFFFFFFF;
            const SIZE_T MAX_REGION_SIZE = 0x10000000;

            while (currentAddr < maxAddr)
            {
                MEMORY_BASIC_INFORMATION mbi = {};

                if (VirtualQuery(reinterpret_cast<LPCVOID>(currentAddr), &mbi, sizeof(mbi)) == 0)
                {
                    currentAddr += 0x1000;
                    continue;
                }

                // Only scan readable, committed memory
                if ((mbi.State == MEM_COMMIT) && Detail::IsReadableProtection(mbi.Protect))
                {
                    SIZE_T regionSize = mbi.RegionSize;
                    if (regionSize > MAX_REGION_SIZE)
                        regionSize = MAX_REGION_SIZE;

                    const uint8_t* data = static_cast<const uint8_t*>(mbi.BaseAddress);

                    // Scan for vtable pointers (8 bytes on x64, 4 bytes on x86)
                    size_t ptrSize = sizeof(uintptr_t);

                    for (size_t offset = 0; offset + ptrSize <= regionSize; ++offset)
                    {
                        // Read potential vtable pointer at current offset
                        uintptr_t ptr = *reinterpret_cast<const uintptr_t*>(data + offset);

                        // Check if it matches our vtable address
                        if (ptr == vtableAddr)
                        {
                            uintptr_t instanceAddr = reinterpret_cast<uintptr_t>(data) + offset;
                            results.push_back(instanceAddr);
                        }
                    }
                }

                currentAddr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            }

            return results;
        }

        // Find vtable instances in a specific module
        inline std::vector<uintptr_t> FindVTableInstancesInModule(uintptr_t vtableAddr,
            const std::string& moduleName)
        {
            std::vector<uintptr_t> results;

            if (vtableAddr == 0)
            {
                std::cerr << "[ERROR] Invalid vtable address\n";
                return results;
            }

            auto [baseAddr, endAddr] = Detail::GetModuleRange(moduleName);

            if (baseAddr == 0 || endAddr == 0)
            {
                std::cerr << "[ERROR] Module not found: " << moduleName << "\n";
                return results;
            }

            uintptr_t currentAddr = baseAddr;
            const SIZE_T MAX_REGION_SIZE = 0x10000000;

            while (currentAddr < endAddr)
            {
                MEMORY_BASIC_INFORMATION mbi = {};

                if (VirtualQuery(reinterpret_cast<LPCVOID>(currentAddr), &mbi, sizeof(mbi)) == 0)
                {
                    currentAddr += 0x1000;
                    continue;
                }

                if ((mbi.State == MEM_COMMIT) && Detail::IsReadableProtection(mbi.Protect))
                {
                    SIZE_T regionSize = mbi.RegionSize;

                    uintptr_t regionEnd = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + regionSize;
                    if (regionEnd > endAddr)
                        regionSize = endAddr - reinterpret_cast<uintptr_t>(mbi.BaseAddress);

                    if (regionSize > MAX_REGION_SIZE)
                        regionSize = MAX_REGION_SIZE;

                    const uint8_t* data = static_cast<const uint8_t*>(mbi.BaseAddress);

                    size_t ptrSize = sizeof(uintptr_t);

                    for (size_t offset = 0; offset + ptrSize <= regionSize; ++offset)
                    {
                        uintptr_t ptr = *reinterpret_cast<const uintptr_t*>(data + offset);

                        if (ptr == vtableAddr)
                        {
                            uintptr_t instanceAddr = reinterpret_cast<uintptr_t>(data) + offset;
                            results.push_back(instanceAddr);
                        }
                    }
                }

                currentAddr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            }

            return results;
        }

        // Find first vtable instance (faster if you only need one)
        inline uintptr_t FindFirstVTableInstance(uintptr_t vtableAddr)
        {
            if (vtableAddr == 0)
            {
                std::cerr << "[ERROR] Invalid vtable address\n";
                return 0;
            }

            uintptr_t currentAddr = 0x10000;
            const uintptr_t maxAddr = 0x00007FFFFFFFFFFF;
            const SIZE_T MAX_REGION_SIZE = 0x10000000;

            while (currentAddr < maxAddr)
            {
                MEMORY_BASIC_INFORMATION mbi = {};

                if (VirtualQuery(reinterpret_cast<LPCVOID>(currentAddr), &mbi, sizeof(mbi)) == 0)
                {
                    currentAddr += 0x1000;
                    continue;
                }

                if ((mbi.State == MEM_COMMIT) && Detail::IsReadableProtection(mbi.Protect))
                {
                    SIZE_T regionSize = mbi.RegionSize;
                    if (regionSize > MAX_REGION_SIZE)
                        regionSize = MAX_REGION_SIZE;

                    const uint8_t* data = static_cast<const uint8_t*>(mbi.BaseAddress);

                    size_t ptrSize = sizeof(uintptr_t);

                    for (size_t offset = 0; offset + ptrSize <= regionSize; ++offset)
                    {
                        uintptr_t ptr = *reinterpret_cast<const uintptr_t*>(data + offset);

                        if (ptr == vtableAddr)
                        {
                            return reinterpret_cast<uintptr_t>(data) + offset;
                        }
                    }
                }

                currentAddr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            }

            return 0;
        }
    }
}