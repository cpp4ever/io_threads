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

#include "io_threads/socket_address.hpp" ///< for io_threads::socket_address

#include <format> ///< for std::format_to, std::formatter
#include <memory> ///< for std::shared_ptr
#include <optional> ///< for std::optional
#include <ostream> ///< for std::ostream
#include <string_view> ///< for std::string_view

namespace io_threads
{

class network_interface final
{
public:
   class system_network_interfaces;

   network_interface() = delete;
   [[nodiscard]] network_interface(network_interface &&rhs) noexcept;
   [[nodiscard]] network_interface(network_interface const &rhs) noexcept;
   ~network_interface();

   network_interface &operator = (network_interface &&rhs) noexcept;
   network_interface &operator = (network_interface const &rhs);

   [[maybe_unused, nodiscard]] bool operator == (network_interface const &rhs) const noexcept
   {
      return bool
      {
         false
         || (m_impl == rhs.m_impl)
         || (
               true
               && (system_name() == rhs.system_name())
               && (ipv4() == rhs.ipv4())
               && (ipv6() == rhs.ipv6())
            )
         ,
      };
   }

   [[nodiscard]] std::string_view friendly_name() const noexcept;

   [[nodiscard]] std::optional<socket_address> const &ipv4() const noexcept;
   [[nodiscard]] std::optional<socket_address> const &ipv6() const noexcept;

   [[nodiscard]] bool is_loopback() const noexcept;

   [[nodiscard]] std::string_view system_name() const noexcept;

private:
   class network_interface_impl;
   std::shared_ptr<network_interface_impl> m_impl;

   [[nodiscard]] explicit network_interface(std::shared_ptr<network_interface_impl> impl) noexcept;
};

std::ostream &operator << (std::ostream &sink, network_interface const &networkInterface);

}

template<>
struct std::formatter<io_threads::network_interface, char>
{
   template<typename parse_context>
   constexpr typename parse_context::iterator parse(parse_context &parseContext)
   {
      return typename parse_context::iterator{parseContext.begin(),};
   }

   template<typename format_context>
   typename format_context::iterator format(io_threads::network_interface const &networkInterface, format_context &formatContext) const
   {
      return typename format_context::iterator
      {
         std::format_to(
            formatContext.out(),
            R"raw({{"friendly_name": "{}", "system_name": "{}", "ipv4": "{}", "ipv6": "{}", "loopback":{}}})raw",
            networkInterface.friendly_name(),
            networkInterface.system_name(),
            networkInterface.ipv4(),
            networkInterface.ipv6(),
            networkInterface.is_loopback()
         ),
      };
   }
};

template<>
struct std::formatter<std::optional<io_threads::network_interface>, char>
{
   template<typename parse_context>
   constexpr typename parse_context::iterator parse(parse_context &parseContext)
   {
      return typename parse_context::iterator{parseContext.begin(),};
   }

   template<typename format_context>
   typename format_context::iterator format(std::optional<io_threads::network_interface> const &networkInterface, format_context &formatContext) const
   {
      return typename format_context::iterator
      {
         (true == networkInterface.has_value())
            ? std::format_to(formatContext.out(), "{}", networkInterface.value())
            : std::format_to(formatContext.out(), "null")
         ,
      };
   }
};
