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

#include "common/logger.hpp" ///< for io_threads::format_string, io_threads::log_system_error
#include "linux/tcp_socket_descriptor.hpp" ///< for io_threads::tcp_socket_descriptor

#include <cstddef> ///< for size_t, std::byte
#include <cstdint> ///< for uint32_t, uint8_t

namespace io_threads
{

enum struct tcp_socket_operation_type : uint8_t
{
   none,
   socket,
   setopt_so_bindtodevice,
   setopt_so_keepalive,
   setopt_ip_tos,
   setopt_tcp_keepcnt,
   setopt_tcp_keepidle,
   setopt_tcp_keepintvl,
   setopt_tcp_nodelay,
   setopt_tcp_syncnt,
   setopt_tcp_user_timeout,
   connect,
   recv,
   send,
   disconnect,
   shutdown,
   close,
};

[[nodiscard]] constexpr format_string<int, std::string> tcp_socket_error_message(tcp_socket_operation_type const tcpSocketOperationType)
{
   switch (tcpSocketOperationType)
   {
   case tcp_socket_operation_type::none: break;
   case tcp_socket_operation_type::socket: return "[tcp_client] failed to create TCP socket: ({}) - {}";
   case tcp_socket_operation_type::setopt_so_bindtodevice: return "[tcp_client] failed to set SO_BINDTODEVICE socket option: ({}) - {}";
   case tcp_socket_operation_type::setopt_so_keepalive: return "[tcp_client] failed to set SO_KEEPALIVE socket option: ({}) - {}";
   case tcp_socket_operation_type::setopt_ip_tos: return "[tcp_client] failed to set IP_TOS socket option: ({}) - {}";
   case tcp_socket_operation_type::setopt_tcp_keepcnt: return "[tcp_client] failed to set TCP_KEEPCNT socket option: ({}) - {}";
   case tcp_socket_operation_type::setopt_tcp_keepidle: return "[tcp_client] failed to set TCP_KEEPIDLE socket option: ({}) - {}";
   case tcp_socket_operation_type::setopt_tcp_keepintvl: return "[tcp_client] failed to set TCP_KEEPINTVL socket option: ({}) - {}";
   case tcp_socket_operation_type::setopt_tcp_nodelay: return "[tcp_client] failed to set TCP_NODELAY socket option: ({}) - {}";
   case tcp_socket_operation_type::setopt_tcp_syncnt: return "[tcp_client] failed to set TCP_SYNCNT socket option: ({}) - {}";
   case tcp_socket_operation_type::setopt_tcp_user_timeout: return "[tcp_client] failed to set TCP_USER_TIMEOUT socket option: ({}) - {}";
   case tcp_socket_operation_type::connect: return "[tcp_client] failed to connect TCP socket: ({}) - {}";
   case tcp_socket_operation_type::recv: return "[tcp_client] failed to recv from TCP socket: ({}) - {}";
   case tcp_socket_operation_type::send: return "[tcp_client] failed to send to TCP socket: ({}) - {}";
   case tcp_socket_operation_type::disconnect: return "[tcp_client] failed to send to TCP socket: ({}) - {}";
   case tcp_socket_operation_type::shutdown: return "[tcp_client] failed to shutdown TCP socket: ({}) - {}";
   case tcp_socket_operation_type::close: return "[tcp_client] failed to close TCP socket: ({}) - {}";
   }
   unreachable();
}

inline void log_socket_error(
   tcp_socket_operation_type const tcpSocketOperationType,
   std::error_code const &errorCode,
   std::source_location const &sourceLocation = std::source_location::current()
)
{
   log_system_error(tcp_socket_error_message(tcpSocketOperationType), errorCode, sourceLocation);
}

struct tcp_socket_operation final
{
   tcp_socket_operation *next{nullptr,};
   tcp_socket_descriptor *descriptor{nullptr,};
   uint32_t const bufferIndex;
   uint32_t bufferOffset{0,};
   tcp_socket_operation_type type{tcp_socket_operation_type::none,};
   std::byte bufferBytes[1]{std::byte{0,},};

   [[nodiscard]] static size_t buffer_bytes_capacity(size_t const totalSize) noexcept
   {
      return totalSize - offsetof(tcp_socket_operation, bufferBytes);
   }

   [[nodiscard]] static size_t total_size(size_t const bytesCapacity) noexcept
   {
      return bytesCapacity + offsetof(tcp_socket_operation, bufferBytes);
   }
};

}
