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

#include <io_threads/tcp_client_config.hpp>

#include <gmock/gmock.h>
#if (defined(_WIN32) || defined(_WIN64))
#  include <winerror.h>
#endif

#include <array>
#include <future>

namespace io_threads::tests
{

template<typename test_client>
void test_tcp_connect_timeout(test_client &testClient, uint16_t const testPort)
{
   auto const testExpectedErrorCodeMatcher
   {
      testing::AnyOf(
#if (defined(__linux__))
         std::make_error_code(std::errc::timed_out)
#elif (defined(_WIN32) || defined(_WIN64))
         std::error_code{WSAEADDRNOTAVAIL, std::system_category()},
         std::error_code{WSAETIMEDOUT, std::system_category()}
#endif
      ),
   };
   constexpr auto testNonRoutableIps = std::to_array<std::string_view>({
      "10.0.0.0",
      "10.255.255.1",
      "10.255.255.255",
      "172.16.0.0",
      "192.168.0.0",
      "192.168.255.255"
   });
   for (auto const &testNonRoutableIp : testNonRoutableIps)
   {
      std::error_code testErrorCode{};
      auto const testSocketAddress = make_socket_address(testNonRoutableIp, testPort, testErrorCode);
      ASSERT_FALSE(testErrorCode) << testErrorCode.value() << ": " << testErrorCode.message();
      ASSERT_TRUE(testSocketAddress.has_value());
      testClient.expect_error(testExpectedErrorCodeMatcher);
      auto const testConnectTimeout = std::chrono::milliseconds{100};
      testClient.expect_ready_to_connect(
         tcp_client_config{tcp_client_address{testSocketAddress.value()}}
            .with_user_timeout(testConnectTimeout)
      );
      auto const testWaitTimeout = std::chrono::seconds{5};
      ASSERT_EQ(std::future_status::ready, testClient.wait_for(testWaitTimeout)) << testNonRoutableIp;
   }
}

}
