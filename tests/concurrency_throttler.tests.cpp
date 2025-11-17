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

#include "testsuite.hpp"

#include <io_threads/concurrency_throttler.hpp>

namespace io_threads::tests
{

namespace
{

using throttler = testsuite;

}

TEST_F(throttler, concurrency_throttler)
{
   constexpr size_t testLimit{10,};
   constexpr std::chrono::seconds testRollingTimeWindow{1,};
   concurrency_throttler testThrottler{testRollingTimeWindow, testLimit,};
   auto const testTime{steady_clock::now(),};
   steady_time testNextSlotTime{};
   std::vector<concurrent_timeslot> testTimeslots{};
   for (size_t testIteration{0,}; testLimit > testIteration; ++testIteration)
   {
      testTimeslots.emplace_back(testThrottler.try_reserve(testTime + std::chrono::milliseconds{testIteration,}, testNextSlotTime));
      ASSERT_TRUE(testTimeslots.back());
      EXPECT_EQ(testNextSlotTime, steady_time{});
   }
   ASSERT_FALSE(testThrottler.try_reserve(testTime, testNextSlotTime));
   EXPECT_EQ(testNextSlotTime, testTime + testRollingTimeWindow);
   testNextSlotTime = steady_time{};
   ASSERT_FALSE(testThrottler.try_reserve(testTime + testRollingTimeWindow - std::chrono::nanoseconds{1,}, testNextSlotTime));
   EXPECT_EQ(testNextSlotTime, testTime + 2 * testRollingTimeWindow - (std::chrono::nanoseconds{1,}));
   for (size_t testIteration{0,}; testLimit > testIteration; ++testIteration)
   {
      testTimeslots[testIteration].submit(testTime + std::chrono::milliseconds{testIteration,});
   }
   testNextSlotTime = steady_time{};
   ASSERT_FALSE(testThrottler.try_reserve(testTime, testNextSlotTime));
   EXPECT_EQ(testNextSlotTime, testTime + testRollingTimeWindow);
   for (size_t testIteration{0,}; testLimit > testIteration; ++testIteration)
   {
      testTimeslots[testIteration] = testThrottler.try_reserve(testTime + testRollingTimeWindow + std::chrono::milliseconds{testIteration,});
      ASSERT_TRUE(testTimeslots[testIteration]);
      testTimeslots[testIteration].submit(testTime + testRollingTimeWindow + std::chrono::milliseconds{testIteration,});
   }
   ASSERT_FALSE(testThrottler.try_reserve(testTime));
   ASSERT_FALSE(testThrottler.try_reserve(testTime + testRollingTimeWindow));
   ASSERT_FALSE(testThrottler.try_reserve(testTime + 2 * testRollingTimeWindow - std::chrono::nanoseconds{1,}));
   auto testSlot{testThrottler.try_reserve(testTime + 2 * testRollingTimeWindow),};
   ASSERT_TRUE(testSlot);
   testSlot.cancel();
}

}
