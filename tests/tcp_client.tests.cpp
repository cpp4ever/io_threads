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

#include "tcp/test_tcp_common.hpp" ///< for test_keep_alive_delay, test_loopback_interface, test_loopback_ip, test_peer_port
#include "tcp/rest/test_rest_client.hpp" ///< for test_rest_client, test_rest_client_traits
#include "testsuite.hpp"

#include <boost/beast.hpp> ///< for boost::beast::tcp_stream
#include <gtest/gtest.h> ///< for TEST

#include <cstdint> ///< for uint16_t
#include <string_view> ///< for std::string_view

namespace io_threads::tests
{

using tcp_client_thread = testsuite;

TEST(tcp_client_thread, tcp_client)
{
   test_rest_client<boost::beast::tcp_stream>();
}

}
