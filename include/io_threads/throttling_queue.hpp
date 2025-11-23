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

#include "io_threads/time.hpp" ///< for io_threads::steady_time, io_threads::time_duration

#include <cstddef> ///< for size_t
#include <mutex> ///< for std::mutex
#include <list> ///< for std::list

namespace io_threads
{

class throttling_queue final
{
public:
   throttling_queue() = delete;
   throttling_queue(throttling_queue &&) = delete;
   throttling_queue(throttling_queue const &) = delete;
   [[nodiscard]] throttling_queue(time_duration rollingTimeWindow, size_t quota);

   throttling_queue &operator = (throttling_queue &&) = delete;
   throttling_queue &operator = (throttling_queue const &) = delete;

   [[nodiscard]] steady_time enqueue(steady_time now);

private:
   time_duration const m_rollingTimeWindow;
   std::mutex m_lock{};
   std::list<steady_time> m_timeslots;
};

}
