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

#pragma once

#include <chrono> ///< for std::chrono::nanoseconds, std::chrono::steady_clock, std::chrono::sys_time, std::chrono::system_clock, std::chrono::time_point

namespace io_threads
{

using time_duration = std::chrono::nanoseconds;
#if (defined(__cpp_lib_chrono) && (__cpp_lib_chrono >= 201907L))
using system_time = std::chrono::sys_time<time_duration>;
using system_clock [[maybe_unused]] = system_time::clock;
#else
using system_clock = std::chrono::system_clock;
using system_time [[maybe_unused]] = std::chrono::time_point<system_clock, time_duration>;
#endif
using steady_clock = std::chrono::steady_clock;
static_assert(true == steady_clock::is_steady);
using steady_time [[maybe_unused]] = steady_clock::time_point;

}
