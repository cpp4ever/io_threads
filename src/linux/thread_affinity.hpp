/*
   Part of the io_threads project (https://github.com/cpp4ever/io_threads), under the MIT License
   SPDX-License-Identifier: MIT

   Copyright (c) 2024 Mikhail Smirnov

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

#pragma once

#include <errno.h> ///< for errno
#include <sched.h> ///< for CPU_SET, cpu_set_t, CPU_ZERO, sched_setaffinity

#include <cstdint> ///< for uint16_t
#include <memory> ///< for std::addressof

namespace io_threads
{

[[nodiscard]] inline int set_thread_affinity(uint16_t const coreCpuId)
{
   cpu_set_t affinityMask;
   CPU_ZERO(std::addressof(affinityMask));
   CPU_SET(coreCpuId, std::addressof(affinityMask));
   return (0 == sched_setaffinity(0, sizeof(affinityMask), std::addressof(affinityMask))) ? 0 : errno;
}

}