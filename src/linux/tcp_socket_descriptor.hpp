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

#include "io_threads/tcp_client.hpp" ///< for io_threads::tcp_client

#include <cstdint> ///< for uint32_t, uint8_t
#include <system_error> ///< for std::error_code

namespace io_threads
{

enum struct tcp_socket_status : uint8_t
{
   none = 0,
   connect,
   ready,
   busy,
   disconnect,
   close,
};

struct tcp_socket_descriptor final
{
   uint32_t const registeredSocketIndex;
   tcp_socket_status tcpSocketStatus{tcp_socket_status::none,};
   uint8_t refsCount{0,};
   tcp_client *tcpClient{nullptr,};
   tcp_socket_descriptor *next{nullptr,};
   std::error_code disconnectReason{};
};

}
