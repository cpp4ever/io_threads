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

#include "windows/tcp_data_transfer_context.hpp" ///< for io_threads::tcp_data_transfer_context
#include "windows/tcp_connectivity_context.hpp" ///< for io_threads::tcp_connectivity_context

#include <WinSock2.h> ///< for INVALID_SOCKET, SOCKET

#include <system_error> ///< for std::error_code

namespace io_threads
{

struct tcp_socket_descriptor final
{
   SOCKET handle{INVALID_SOCKET};
   tcp_data_transfer_context *recvContext{nullptr};
   tcp_data_transfer_context *sendContext{nullptr};
   tcp_connectivity_context *connectivityContext{nullptr};
   std::error_code disconnectReason{};
};

}