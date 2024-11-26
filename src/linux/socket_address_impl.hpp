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

#include "common/logger.hpp" ///< for io_threads::log_error, io_threads::log_system_error
#include "common/utility.hpp" ///< for io_threads::to_underlying, io_threads::unreachable
#include "io_threads/socket_address.hpp" ///< for io_threads::socket_address

#include <netinet/in.h> ///< for sockaddr_in, sockaddr_in6

#include <algorithm> ///< for std::max
#include <array> ///< for std::to_array
#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <cstddef> ///< for size_t
#include <cstdint> ///< for uint16_t
#include <memory> ///< for std::addressof, std::make_shared, std::shared_ptr
#include <source_location> ///< for std::source_location
#include <string> ///< for std::string, std::wstring
#include <string_view> ///< for std::string_view
#include <system_error> ///< for std::error_code, std::system_category

namespace io_threads
{

struct sockaddr_inet
{
   union
   {
      sockaddr_in ipv4;
      sockaddr_in6 ipv6;
   };
};

class socket_address::socket_address_impl final
{
public:
   socket_address_impl() = delete;
   socket_address_impl(socket_address_impl &&) = delete;
   socket_address_impl(socket_address_impl const &) = delete;

   [[nodiscard]] explicit socket_address_impl(sockaddr_in const &ipv4Address) :
      socket_address_impl{sockaddr_inet{.ipv4{ipv4Address}}}
   {}

   [[nodiscard]] explicit socket_address_impl(sockaddr_in6 const &ipv6Address) :
      socket_address_impl{sockaddr_inet{.ipv6{ipv6Address}}}
   {}

   [[nodiscard]] explicit socket_address_impl(sockaddr_inet const &address) :
      m_sockaddr{address}
   {
   }

   [[nodiscard]] explicit operator std::string() const
   {
      return m_address;
   }

   [[nodiscard]] explicit operator std::string_view() const noexcept
   {
      return m_address;
   }

   socket_address_impl &operator = (socket_address_impl &&) = delete;
   socket_address_impl &operator = (socket_address_impl const &) = delete;

   [[nodiscard]] sockaddr_inet const &sockaddr() const noexcept
   {
      return m_sockaddr;
   }

   static std::shared_ptr<socket_address_impl> parse(
      std::string_view const utf8Address,
      uint16_t const port,
      std::error_code &errorCode
   )
   {
      (void)utf8Address;
      (void)port;
      (void)errorCode;
      return {};
   }

private:
   sockaddr_inet m_sockaddr;
   std::string m_address{};
};

}
