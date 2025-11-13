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

#include <io_threads/throttling_queue.hpp>

namespace io_threads::tests
{

namespace
{

using throttler = testsuite;

}

TEST_F(throttler, throttling_queue)
{
   constexpr auto testLambda
   {
      [] (auto const testLimit)
      {
         auto const testQueueCapacity{testLimit * 2,};
         constexpr std::chrono::seconds testRollingTimeWindow{1,};
         throttling_queue testThrottler{testRollingTimeWindow, static_cast<size_t>(testLimit),};
         auto const testTime{system_clock::now(),};
         for (auto testIteration{0,}; testQueueCapacity > testIteration; ++testIteration)
         {
            EXPECT_EQ(testTime + testRollingTimeWindow * ((testIteration >= testLimit) ? 1 : 0), testThrottler.enqueue(testTime));
         }
         for (auto testIteration{0,}; testQueueCapacity > testIteration; ++testIteration)
         {
            EXPECT_EQ(
               testTime + testRollingTimeWindow * ((testIteration >= testLimit) ? 3 : 2),
               testThrottler.enqueue(testTime + testRollingTimeWindow)
            );
         }
      }
   };
   testLambda(10);
   testLambda(11);
}

}
