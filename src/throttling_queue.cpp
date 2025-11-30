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
#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <cstddef> ///< for size_t
#include <memory> ///< for std::construct_at, std::destroy_at
#include <mutex> ///< for std::scoped_lock
#include <new> ///< for operator delete, operator new, std::align_val_t

namespace io_threads
{

throttling_queue::throttling_queue(time_duration const rollingTimeWindow, size_t const quota) :
   m_rollingTimeWindow{rollingTimeWindow,}
{
   assert(time_duration::zero() < rollingTimeWindow);
   assert(0 < quota);
   m_timeslotPool = std::bit_cast<timeslot *>(::operator new(quota * sizeof(timeslot), std::align_val_t{alignof(timeslot),}));
   auto *nextTimeslot{m_timeslotPool,};
   for (size_t index{0,}; quota > index; ++index, ++nextTimeslot)
   {
      if (nullptr == m_timeslotHead)
      {
         assert(nullptr == m_timeslotTail);
         m_timeslotTail = m_timeslotHead = std::construct_at(nextTimeslot, timeslot{});
      }
      else
      {
         assert(nullptr == m_timeslotTail->next);
         m_timeslotTail->next = std::construct_at(nextTimeslot, timeslot{});
         m_timeslotTail = m_timeslotTail->next;
         assert(nullptr == m_timeslotTail->next);
      }
   }
}

throttling_queue::~throttling_queue()
{
   while (nullptr != m_timeslotHead)
   {
      auto *timeslot{m_timeslotHead,};
      m_timeslotHead = timeslot->next;
      std::destroy_at(timeslot);
   }
   ::operator delete(m_timeslotPool, std::align_val_t{alignof(timeslot),});
}

steady_time throttling_queue::enqueue(steady_time const now)
{
   assert(nullptr != m_timeslotHead);
   assert(nullptr != m_timeslotTail);
   assert(nullptr == m_timeslotTail->next);
   [[maybe_unused]] std::scoped_lock const timeslotGuard{m_timeslotLock,};
   auto &timeslot{*m_timeslotHead};
   timeslot.timestamp = std::max(now, timeslot.timestamp + m_rollingTimeWindow);
   if (m_timeslotHead != m_timeslotTail)
   {
      m_timeslotHead = timeslot.next;
      timeslot.next = nullptr;
      m_timeslotTail->next = std::addressof(timeslot);
      m_timeslotTail = std::addressof(timeslot);
   }
   else
   {
      assert(nullptr == m_timeslotHead->next);
   }
   assert(nullptr == m_timeslotTail->next);
   return timeslot.timestamp;
}

}
