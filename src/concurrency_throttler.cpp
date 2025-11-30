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

#include "io_threads/concurrency_throttler.hpp" ///< for io_threads::concurrency_throttler
#include "io_threads/time.hpp" ///< for io_threads::steady_time, io_threads::time_duration

#include <cassert> ///< for assert
#include <cstddef> ///< for size_t
#include <memory> ///< for std::addressof
#include <mutex> ///< for std::scoped_lock

namespace io_threads
{

concurrency_throttler::busy_timeslots::~busy_timeslots()
{
   assert(nullptr == m_head);
   assert(nullptr == m_tail);
}

void concurrency_throttler::busy_timeslots::push(timeslot &item)
{
   assert(nullptr == item.next);
   if (nullptr == m_tail)
   {
      assert(nullptr == m_head);
      m_head = m_tail = std::addressof(item);
   }
   else
   {
      m_tail->next = std::addressof(item);
      m_tail = std::addressof(item);
   }
}

concurrency_throttler::timeslot &concurrency_throttler::busy_timeslots::pop()
{
   assert(nullptr != m_head);
   auto &item{*m_head,};
   m_head = m_head->next;
   if (nullptr == m_head)
   {
      assert(std::addressof(item) == m_tail);
      m_tail = nullptr;
   }
   item.next = nullptr;
   return item;
}

steady_time concurrency_throttler::busy_timeslots::next_expiration_time() const
{
   assert(nullptr != m_head);
   return m_head->expirationTime;
}

concurrency_throttler::concurrent_timeslot::concurrent_timeslot(concurrent_timeslot &&rhs) noexcept :
   m_throttler{rhs.m_throttler,},
   m_slot{rhs.m_slot,}
{
   rhs.m_throttler = nullptr;
   rhs.m_slot = nullptr;
}

concurrency_throttler::concurrent_timeslot::concurrent_timeslot(concurrency_throttler &throttler) noexcept :
   m_throttler{std::addressof(throttler),},
   m_slot{throttler.m_freeTimeslots,}
{
   assert(nullptr != throttler.m_freeTimeslots);
   throttler.m_freeTimeslots = m_slot->next;
   m_slot->next = nullptr;
}

concurrency_throttler::concurrent_timeslot::~concurrent_timeslot()
{
   assert(nullptr == m_throttler);
   assert(nullptr == m_slot);
}

concurrency_throttler::concurrent_timeslot &concurrency_throttler::concurrent_timeslot::operator = (concurrent_timeslot &&rhs) noexcept
{
   assert(nullptr == m_throttler);
   assert(nullptr == m_slot);
   m_throttler = rhs.m_throttler;
   rhs.m_throttler = nullptr;
   m_slot = rhs.m_slot;
   rhs.m_slot = nullptr;
   return *this;
}

void concurrency_throttler::concurrent_timeslot::cancel()
{
   assert(nullptr != m_throttler);
   assert(nullptr != m_slot);
   [[maybe_unused]] std::scoped_lock const timeslotGuard{m_throttler->m_timeslotLock,};
   m_slot->next = m_throttler->m_freeTimeslots;
   m_throttler->m_freeTimeslots = m_slot;
   m_throttler = nullptr;
   m_slot = nullptr;
}

void concurrency_throttler::concurrent_timeslot::submit(steady_time const now)
{
   assert(nullptr != m_throttler);
   assert(nullptr != m_slot);
   [[maybe_unused]] std::scoped_lock const timeslotGuard{m_throttler->m_timeslotLock,};
   m_slot->expirationTime = now + m_throttler->m_rollingTimeWindow;
   m_throttler->m_busyTimeslots.push(*m_slot);
   m_throttler = nullptr;
   m_slot = nullptr;
}

concurrency_throttler::concurrency_throttler(time_duration const rollingTimeWindow, size_t const quota) :
   m_rollingTimeWindow{rollingTimeWindow,}
{
   assert(rollingTimeWindow > time_duration::zero());
   assert(quota > 0);
   m_timeslotPool = std::bit_cast<timeslot *>(::operator new(quota * sizeof(timeslot), std::align_val_t{alignof(timeslot),}));
   auto *nextTimeslot{m_timeslotPool,};
   for (size_t index{0,}; quota > index; ++index, ++nextTimeslot)
   {
      m_freeTimeslots = std::construct_at(nextTimeslot, timeslot{.next = m_freeTimeslots,});
   }
}

concurrency_throttler::~concurrency_throttler()
{
   while (false == m_busyTimeslots.empty())
   {
      std::destroy_at(std::addressof(m_busyTimeslots.pop()));
   }
   while (nullptr != m_freeTimeslots)
   {
      auto *timeslot{m_freeTimeslots,};
      m_freeTimeslots = timeslot->next;
      std::destroy_at(timeslot);
   }
   ::operator delete(m_timeslotPool, std::align_val_t{alignof(timeslot),});
}

concurrency_throttler::concurrent_timeslot concurrency_throttler::try_reserve(steady_time const now)
{
   [[maybe_unused]] std::scoped_lock const timeslotGuard{m_timeslotLock,};
   check_expired(now);
   if (nullptr == m_freeTimeslots)
   {
      return concurrent_timeslot{};
   }
   return concurrent_timeslot{*this,};
}

concurrency_throttler::concurrent_timeslot concurrency_throttler::try_reserve(steady_time const now, steady_time &nextSlotTime)
{
   [[maybe_unused]] std::scoped_lock const timeslotGuard{m_timeslotLock,};
   check_expired(now);
   if (nullptr == m_freeTimeslots)
   {
      nextSlotTime = ((true == m_busyTimeslots.empty()) ? (now + m_rollingTimeWindow) : m_busyTimeslots.next_expiration_time());
      return concurrent_timeslot{};
   }
   return concurrent_timeslot{*this,};
}

void concurrency_throttler::check_expired(steady_time const now)
{
   while ((false == m_busyTimeslots.empty()) && (now >= m_busyTimeslots.next_expiration_time()))
   {
      auto &timeslot{m_busyTimeslots.pop(),};
      timeslot.next = m_freeTimeslots;
      m_freeTimeslots = std::addressof(timeslot);
   }
}

}
