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

#include <io_threads/system_network_interfaces.hpp>

namespace io_threads::tests
{

namespace
{

using network_interface = testsuite;

}

TEST_F(network_interface, network_interface)
{
   system_network_interfaces testSystemNetworkInterfaces{};
   auto const testLoopbackInterface = testSystemNetworkInterfaces.loopback();
   ASSERT_TRUE(testLoopbackInterface.has_value());
   EXPECT_FALSE(testLoopbackInterface->friendly_name().empty());
   EXPECT_TRUE(testLoopbackInterface->ip_v4().has_value() || testLoopbackInterface->ip_v6().has_value());
   EXPECT_TRUE(testLoopbackInterface->is_loopback());
   EXPECT_FALSE(testLoopbackInterface->system_name().empty());
   EXPECT_EQ(testLoopbackInterface, testSystemNetworkInterfaces.find(testLoopbackInterface->system_name()));
   if (true == testLoopbackInterface->ip_v4().has_value())
   {
      EXPECT_EQ(testLoopbackInterface, (testSystemNetworkInterfaces.find(std::string_view{testLoopbackInterface->ip_v4().value(),})));
   }
   if (true == testLoopbackInterface->ip_v6().has_value())
   {
      EXPECT_EQ(testLoopbackInterface, (testSystemNetworkInterfaces.find(std::string_view{testLoopbackInterface->ip_v6().value(),})));
   }
   EXPECT_EQ(std::format("{}", testLoopbackInterface), std::format("{}", testLoopbackInterface.value()));
}

}
