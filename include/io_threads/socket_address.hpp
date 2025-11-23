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

#include <cstdint> ///< for uint16_t
#include <format> ///< for std::format_to, std::formatter
#include <memory> ///< for std::shared_ptr
#include <optional> ///< for std::optional
#include <ostream> ///< for std::ostream
#include <string_view> ///< for std::string_view
#include <system_error> ///< for std::error_code

namespace io_threads
{

class socket_address final
{
public:
   class socket_address_impl;

   socket_address() = delete;
   [[nodiscard]] socket_address(socket_address &&rhs) noexcept;
   [[nodiscard]] socket_address(socket_address const &rhs) noexcept;
   [[nodiscard]] explicit socket_address(std::shared_ptr<socket_address_impl> impl) noexcept;

   [[nodiscard]] explicit operator std::string_view() const noexcept;

   [[nodiscard]] socket_address_impl const *operator -> () const noexcept;

   socket_address &operator = (socket_address &&rhs) noexcept;
   socket_address &operator = (socket_address const &rhs);

   [[maybe_unused, nodiscard]] bool operator == (socket_address const &rhs) const noexcept
   {
      return bool{std::string_view{*this,} == std::string_view{rhs,},};
   }

   [[nodiscard]] bool ipv4() const noexcept;
   [[nodiscard]] bool ipv6() const noexcept;

private:
   std::shared_ptr<socket_address_impl> m_impl;
};

std::ostream &operator << (std::ostream &sink, socket_address const &socketAddress);

[[nodiscard]] std::optional<socket_address> make_socket_address(std::string_view const &ipport, std::error_code &errorCode);
[[nodiscard]] std::optional<socket_address> make_socket_address(std::string_view const &ip, uint16_t port, std::error_code &errorCode);

}

template<>
struct std::formatter<io_threads::socket_address, char>
{
   template<typename parse_context>
   constexpr typename parse_context::iterator parse(parse_context &parseContext)
   {
      return typename parse_context::iterator{parseContext.begin(),};
   }

   template<typename format_context>
   typename format_context::iterator format(io_threads::socket_address const &socketAddress, format_context &formatContext) const
   {
      return typename format_context::iterator{std::format_to(formatContext.out(), "{}", std::string_view{socketAddress,}),};
   }
};

template<>
struct std::formatter<std::optional<io_threads::socket_address>, char>
{
   template<typename parse_context>
   constexpr typename parse_context::iterator parse(parse_context &parseContext)
   {
      return typename parse_context::iterator{parseContext.begin(),};
   }

   template<typename format_context>
   typename format_context::iterator format(std::optional<io_threads::socket_address> const &socketAddress, format_context &formatContext) const
   {
      return typename format_context::iterator
      {
         (true == socketAddress.has_value())
            ? std::format_to(formatContext.out(), "{}", socketAddress.value())
            : std::format_to(formatContext.out(), "null")
         ,
      };
   }
};
