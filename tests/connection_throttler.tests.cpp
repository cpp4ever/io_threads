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

#include <io_threads/connection_throttler.hpp>
#include <io_threads/system_network_interfaces.hpp>

#include <array>

namespace io_threads::tests
{

namespace
{

using throttler = testsuite;

}

TEST_F(throttler, connection_throttler)
{
   constexpr auto testLoopbackIps{std::to_array<std::string_view>({"127.0.0.1", "::1",}),};
   system_network_interfaces testSystemNetworkInterfaces{};
   std::vector<socket_address> testLoopbackAddresses{};
   testLoopbackAddresses.reserve(testLoopbackIps.size());
   auto const testTime{steady_clock::now(),};
   for (auto const &testLoopbackIp : testLoopbackIps)
   {
      std::error_code testErrorCode{};
      auto const testLoopbackAddress{make_socket_address(testLoopbackIp, 80, testErrorCode),};
      ASSERT_FALSE(testErrorCode) << testErrorCode.value() << ": " << testErrorCode.message();
      ASSERT_TRUE(testLoopbackAddress.has_value()) << testLoopbackIp;
      testLoopbackAddresses.emplace_back(testLoopbackAddress.value());
   }
   {
      constexpr std::chrono::seconds testRollingTimeWindow{1,};
      connection_throttler testThrottler{testRollingTimeWindow, 1,};
      for (auto const &testLoopbackAddress : testLoopbackAddresses)
      {
         EXPECT_EQ(testTime, testThrottler.enqueue(tcp_client_address{testLoopbackAddress,}, testTime));
         EXPECT_EQ(testTime + testRollingTimeWindow, testThrottler.enqueue(tcp_client_address{testLoopbackAddress,}, testTime));
      }
      if (auto const &testLoopbackInterface{testSystemNetworkInterfaces.loopback(),}; true == testLoopbackInterface.has_value())
      {
         for (auto const &testLoopbackAddress : testLoopbackAddresses)
         {
            EXPECT_EQ(testTime, testThrottler.enqueue(tcp_client_address{testLoopbackInterface.value(), testLoopbackAddress,}, testTime));
            EXPECT_EQ(testTime + testRollingTimeWindow, testThrottler.enqueue(tcp_client_address{testLoopbackInterface.value(), testLoopbackAddress,}, testTime));
         }
      }
   }
   if (auto const &testLoopbackInterface{testSystemNetworkInterfaces.loopback(),}; true == testLoopbackInterface.has_value())
   {
      constexpr std::chrono::seconds testRollingTimeWindow{1,};
      connection_throttler testThrottler{std::vector<network_interface>{testLoopbackInterface.value(),}, testRollingTimeWindow, 1,};
      for (auto const &testLoopbackAddress : testLoopbackAddresses)
      {
         EXPECT_EQ(testTime, testThrottler.enqueue(tcp_client_address{testLoopbackAddress,}, testTime));
         EXPECT_EQ(testTime + testRollingTimeWindow, testThrottler.enqueue(tcp_client_address{testLoopbackAddress,}, testTime));
         EXPECT_EQ(testTime, testThrottler.enqueue(tcp_client_address{testLoopbackInterface.value(), testLoopbackAddress,}, testTime));
         EXPECT_EQ(testTime + testRollingTimeWindow, testThrottler.enqueue(tcp_client_address{testLoopbackInterface.value(), testLoopbackAddress,}, testTime));
      }
   }
}

}
