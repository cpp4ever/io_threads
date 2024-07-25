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

#include "common/logger.hpp" ///< for io_threads::log_system_error
#include "common/utility.hpp" ///< for io_threads::unreachable
#include "io_threads/socket_address.hpp" ///< for io_threads::socket_address
#include "linux/addrinfo_error.hpp" ///< for io_threads::make_addrinfo_error_code
#include "linux/socket_address_impl.hpp" ///< for io_threads::socket_address_impl

#include <netdb.h> ///< for addrinfo, AI_ALL, freeaddrinfo, getaddrinfo
#include <netinet/in.h> ///< for htons, IPPROTO_TCP, sockaddr_in, sockaddr_in6
#include <sys/socket.h> ///< for AF_INET, AF_INET6, sa_family_t, SOCK_STREAM

#include <bit> ///< for std::bit_cast
#include <cstdint> ///< for uint16_t
#include <memory> ///< for std::addressof, std::make_shared
#include <string> ///< for std::string, std::to_string
#include <string_view> ///< for std::string_view
#include <vector> ///< for std::vector

namespace io_threads
{

namespace
{

[[nodiscard]] std::vector<socket_address> resolve_domain_name(
   sa_family_t const addressFamily,
   std::string_view const &host,
   uint16_t const port
)
{
   std::string const nodeName{host,};
   auto const service{(0 < port) ? std::to_string(port) : std::string{},};
   addrinfo const hints
   {
      .ai_flags = AI_ALL,
      .ai_family = addressFamily,
      .ai_socktype = SOCK_STREAM,
      .ai_protocol = IPPROTO_TCP,
      .ai_addrlen = 0,
      .ai_addr = nullptr,
      .ai_canonname = nullptr,
      .ai_next = nullptr,
   };
   addrinfo *result{nullptr,};
   if (
      auto const errorCode{getaddrinfo(nodeName.data(), (0 < port) ? service.data() : nullptr, std::addressof(hints), std::addressof(result)),};
      0 != errorCode
   )
   {
      log_system_error("[dns_resolver] failed to resolve domain name: ({}) - {}", make_addrinfo_error_code(errorCode));
      unreachable();
   }
   std::vector<socket_address> addresses{};
   for (auto const *address{result}; nullptr != address; address = address->ai_next)
   {
      if (AF_INET == address->ai_family)
      {
         auto &addr{*std::bit_cast<sockaddr_in*>(address->ai_addr),};
         if (0 == addr.sin_port)
         {
            addr.sin_port = htons(port);
         }
         addresses.push_back(socket_address{std::make_shared<socket_address::socket_address_impl>(addr),});
      }
      else if (AF_INET6 == address->ai_family)
      {
         auto &addr{*std::bit_cast<sockaddr_in6 *>(address->ai_addr),};
         if (0 == addr.sin6_port)
         {
            addr.sin6_port = htons(port);
         }
         addresses.push_back(socket_address{std::make_shared<socket_address::socket_address_impl>(addr),});
      }
   }
   freeaddrinfo(result);
   return addresses;
}

}

}
