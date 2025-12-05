/*
   Part of the io_threads project (https://github.com/cpp4ever/io_threads), under the MIT License
   SPDX-License-Identifier: MIT

   Copyright (c) 2024-2025 Mikhail Smirnov

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.
*/

#include "testsuite.hpp"

#if (defined(__linux__))
#  include <sched.h>
#elif (defined(_WIN32) || defined(_WIN64))
#  include <Windows.h>
#endif

#include <algorithm>
#include <chrono>

namespace io_threads::tests
{

cpu_id testsuite::first_cpu()
{
#if (defined(__linux__))
   cpu_set_t processAffinityMask{};
   CPU_ZERO(std::addressof(processAffinityMask));
   EXPECT_EQ(0, sched_getaffinity(getpid(), sizeof(processAffinityMask), std::addressof(processAffinityMask)))
      << std::error_code{errno, std::generic_category(),}
   ;
   auto const numberOfCpus{static_cast<uint32_t>(CPU_COUNT(std::addressof(processAffinityMask))),};
   for (uint32_t cpuIndex{0,}; numberOfCpus > cpuIndex; ++cpuIndex)
   {
      if (CPU_ISSET(cpuIndex, std::addressof(processAffinityMask)))
      {
         return cpu_id{cpuIndex,};
      }
   }
#elif (defined(_WIN32) || defined(_WIN64))
   DWORD_PTR processAffinityMask{0,};
   DWORD_PTR systemAffinityMask{0,};
   EXPECT_EQ(TRUE, GetProcessAffinityMask(GetCurrentProcess(), std::addressof(processAffinityMask), std::addressof(systemAffinityMask)))
      << std::error_code{static_cast<int>(GetLastError()), std::system_category(),}
   ;
   for (uint32_t cpuIndex{0,}; (sizeof(DWORD_PTR) * CHAR_BIT) > cpuIndex; ++cpuIndex)
   {
      if (auto const cpuMask{DWORD_PTR{1,} << cpuIndex,}; (processAffinityMask & cpuMask) == cpuMask)
      {
         return cpu_id{cpuIndex,};
      }
      else if (cpuMask > processAffinityMask)
      {
         break;
      }
   }
#endif
   return cpu_id{0,};
}

cpu_id testsuite::next_cpu(cpu_id const cpuId)
{
#if (defined(__linux__))
   cpu_set_t processAffinityMask{};
   CPU_ZERO(std::addressof(processAffinityMask));
   EXPECT_EQ(0, sched_getaffinity(getpid(), sizeof(processAffinityMask), std::addressof(processAffinityMask)))
      << std::error_code{errno, std::generic_category(),}
   ;
   auto const numberOfCpus{static_cast<uint32_t>(CPU_COUNT(std::addressof(processAffinityMask))),};
   auto const cpuIndex{static_cast<uint32_t>(cpuId),};
   auto firstIteration{true,};
   for (auto nextCpuIndex{cpuIndex + 1,}; cpuIndex != nextCpuIndex; ++nextCpuIndex)
   {
      if (CPU_ISSET(cpuIndex, std::addressof(processAffinityMask)))
      {
         return cpu_id{nextCpuIndex,};
      }
      else if (numberOfCpus < nextCpuIndex)
      {
         if (false == firstIteration)
         {
            break;
         }
         firstIteration = false;
         nextCpuIndex = 0;
      }
   }
#elif (defined(_WIN32) || defined(_WIN64))
   DWORD_PTR processAffinityMask{0,};
   DWORD_PTR systemAffinityMask{0,};
   EXPECT_EQ(TRUE, GetProcessAffinityMask(GetCurrentProcess(), std::addressof(processAffinityMask), std::addressof(systemAffinityMask)))
      << std::error_code{static_cast<int>(GetLastError()), std::system_category(),}
   ;
   auto const cpuIndex{static_cast<uint32_t>(cpuId),};
   auto firstIteration{true,};
   for (auto nextCpuIndex{cpuIndex + 1,}; cpuIndex != nextCpuIndex; ++nextCpuIndex)
   {
      if (auto const nextCpuMask{DWORD_PTR{1,} << nextCpuIndex,}; (processAffinityMask & nextCpuMask) == nextCpuMask)
      {
         return cpu_id{nextCpuIndex,};
      }
      else if (nextCpuMask > processAffinityMask)
      {
         if (false == firstIteration)
         {
            break;
         }
         firstIteration = false;
         nextCpuIndex = 0;
      }
   }
#endif
   return cpuId;
}

std::string testsuite::random_string(size_t const length)
{
   std::string randomString;
   randomString.reserve(length + 1);
   std::generate_n(
      std::back_inserter(randomString),
      length,
      [this] ()
      {
         static constexpr char charArray[] =
         {
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
         };
         return charArray[random_number<size_t>(0, sizeof(charArray) - 1)];
      }
   );
   return randomString;
}

void testsuite::SetUp()
{
   super::SetUp();

   m_randomEngine.seed(std::chrono::system_clock::now().time_since_epoch().count());
}

}
