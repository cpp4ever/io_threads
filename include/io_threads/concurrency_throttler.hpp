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

#include "io_threads/time.hpp" ///< for io_threads::steady_time, io_threads::time_duration

#include <cstddef> ///< for size_t
#include <mutex> ///< for std::mutex
#include <vector> ///< for std::vector

namespace io_threads
{

class concurrency_throttler final
{
private:
   struct timeslot
   {
      timeslot *next{nullptr,};
      steady_time expirationTime;
   };

   class busy_timeslots final
   {
   public:
      [[nodiscard]] busy_timeslots() noexcept = default;
      busy_timeslots(busy_timeslots &&) = delete;
      busy_timeslots(busy_timeslots const &) = delete;
      ~busy_timeslots();

      busy_timeslots &operator = (busy_timeslots &&) = delete;
      busy_timeslots &operator = (busy_timeslots const &) = delete;

      void push(timeslot &item);
      [[nodiscard]] timeslot &pop();

      [[nodiscard]] size_t size() const noexcept
      {
         return m_size;
      }

      [[nodiscard]] steady_time next_expiration_time() const;

   private:
      timeslot *m_head{nullptr,};
      timeslot *m_tail{nullptr,};
      size_t m_size{0,};
   };

public:
   class concurrent_timeslot final
   {
   public:
      [[maybe_unused, nodiscard]] concurrent_timeslot() noexcept = default;
      [[nodiscard]] concurrent_timeslot(concurrent_timeslot &&rhs) noexcept;
      concurrent_timeslot(concurrent_timeslot const &) = delete;
      [[nodiscard]] explicit concurrent_timeslot(concurrency_throttler &throttler) noexcept;
      ~concurrent_timeslot();

      [[maybe_unused, nodiscard]] explicit operator bool () const noexcept
      {
         return nullptr != m_throttler;
      }

      concurrent_timeslot &operator = (concurrent_timeslot &&rhs) noexcept;
      concurrent_timeslot &operator = (concurrent_timeslot const &) = delete;

      void cancel();
      void submit(steady_time now);

   private:
      concurrency_throttler *m_throttler{nullptr,};
      timeslot *m_slot{nullptr,};
   };

   concurrency_throttler() = delete;
   concurrency_throttler(concurrency_throttler &&) = delete;
   concurrency_throttler(concurrency_throttler const &) = delete;
   [[nodiscard]] concurrency_throttler(time_duration rollingTimeWindow, size_t quota);
   ~concurrency_throttler();

   concurrency_throttler &operator = (concurrency_throttler &&) = delete;
   concurrency_throttler &operator = (concurrency_throttler const &) = delete;

   [[nodiscard]] concurrent_timeslot try_reserve(steady_time now);
   [[nodiscard]] concurrent_timeslot try_reserve(steady_time now, steady_time &nextSlotTime);

private:
   time_duration const m_rollingTimeWindow;
   std::mutex m_lock{};
   timeslot *m_freeTimeslots{nullptr,};
   busy_timeslots m_busyTimeslots{};
   std::vector<timeslot> m_allTimeslots;

   void check_expired(steady_time now);
};

using concurrent_timeslot [[maybe_unused]] = concurrency_throttler::concurrent_timeslot;

}
