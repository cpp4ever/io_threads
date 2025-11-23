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

#pragma once

#include "common/logger.hpp" ///< for io_threads::log_system_error
#include "common/utility.hpp" ///< for io_threads::unreachable
#include "io_threads/socket_address.hpp" ///< for io_threads::socket_address
#include "windows/socket_address_impl.hpp" ///< for io_threads::socket_address_impl

/// for
///   ADDRESS_FAMILY,
///   AF_INET,
///   AF_INET6,
///   AI_ALL,
///   ERROR_SUCCESS,
///   htons,
///   IPPROTO_TCP,
///   SOCK_STREAM,
///   SOCKADDR_IN
#include <WinSock2.h>
#include <ws2ipdef.h> ///< for SOCKADDR_IN6
#include <WS2tcpip.h> ///< for ADDRINFO, freeaddrinfo, getaddrinfo

#include <bit> ///< for std::bit_cast
#include <cstdint> ///< for uint16_t
#include <memory> ///< for std::addressof, std::make_shared
#include <string> ///< for std::string, std::to_string
#include <string_view> ///< for std::string_view
#include <vector> ///< for std::vector

#pragma comment(lib, "WS2_32")

namespace io_threads
{

namespace
{

[[nodiscard]] std::vector<socket_address> resolve_domain_name(
   ADDRESS_FAMILY const addressFamily,
   std::string_view const &host,
   uint16_t const port
)
{
   std::string const nodeName{host,};
   auto const service{(0 < port) ? std::to_string(port) : std::string{},};
   ADDRINFO const hints
   {
      .ai_flags = AI_ALL,
      .ai_family = addressFamily,
      .ai_socktype = SOCK_STREAM,
      .ai_protocol = IPPROTO_TCP,
      .ai_addrlen = 0,
      .ai_canonname = nullptr,
      .ai_addr = nullptr,
      .ai_next = nullptr,
   };
   ADDRINFO *result{nullptr,};
   if (
      auto const errorCode
      {
         getaddrinfo(
            nodeName.data(),
            (0 < port) ? service.data() : nullptr,
            std::addressof(hints),
            std::addressof(result)
         ),
      };
      ERROR_SUCCESS != errorCode
   )
   {
      log_system_error("[dns_resolver] failed to getaddrinfo: ({}) - {}", errorCode);
      unreachable();
   }
   std::vector<socket_address> addresses{};
   for (auto const *address{result,}; nullptr != address; address = address->ai_next)
   {
      if (AF_INET == address->ai_family)
      {
         auto &sockaddr{*std::bit_cast<SOCKADDR_IN *>(address->ai_addr),};
         if (0 == sockaddr.sin_port)
         {
            sockaddr.sin_port = htons(port);
         }
         addresses.push_back(socket_address{std::make_shared<socket_address::socket_address_impl>(sockaddr),});
      }
      else if (AF_INET6 == address->ai_family)
      {
         auto &sockaddr{*std::bit_cast<SOCKADDR_IN6 *>(address->ai_addr),};
         if (0 == sockaddr.sin6_port)
         {
            sockaddr.sin6_port = htons(port);
         }
         addresses.push_back(socket_address{std::make_shared<socket_address::socket_address_impl>(sockaddr),});
      }
   }
   freeaddrinfo(result);
   return addresses;
}

}

}
