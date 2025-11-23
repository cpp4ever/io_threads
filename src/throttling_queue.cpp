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

#include "io_threads/time.hpp" ///< for io_threads::steady_time, io_threads::time_duration
#include "io_threads/throttling_queue.hpp" ///< for io_threads::throttling_queue

#include <algorithm> ///< for std::max
#include <cassert> ///< for assert
#include <cstddef> ///< for size_t
#include <mutex> ///< for std::scoped_lock

namespace io_threads
{

throttling_queue::throttling_queue(time_duration const rollingTimeWindow, size_t const quota) :
   m_rollingTimeWindow{rollingTimeWindow,},
   m_timeslots{quota, steady_time{time_duration::zero(),},}
{
   assert(rollingTimeWindow > time_duration::zero());
   assert(quota > 0);
}

steady_time throttling_queue::enqueue(steady_time const now)
{
   [[maybe_unused]] std::scoped_lock const throttlerGuard{m_lock,};
   auto timeslot{m_timeslots.begin(),};
   *timeslot = std::max(now, *timeslot + m_rollingTimeWindow);
   m_timeslots.splice(m_timeslots.end(), m_timeslots, timeslot);
   return *timeslot;
}

}
