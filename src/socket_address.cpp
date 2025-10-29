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

#include "io_threads/socket_address.hpp" ///< for io_threads::socket_address
#if (defined(__linux__))
#  include "linux/socket_address_impl.hpp" ///< for io_threads::socket_address::socket_address_impl
#elif (defined(_WIN32) || defined(_WIN64))
#  include "windows/socket_address_impl.hpp" ///< for io_threads::socket_address::socket_address_impl
#endif

#include <cassert> ///< for assert
#include <cstdint> ///< for uint16_t
#include <format> ///< for std::format
#include <memory> ///< for std::shared_ptr
#include <optional> ///< for std::nullopt, std::optional
#include <ostream> ///< for std::ostream
#include <string> ///< for std::string
#include <string_view> ///< for std::string_view
#include <system_error> ///< for std::error_code
#include <utility> ///< for std::move

namespace io_threads
{

socket_address::socket_address(socket_address &&rhs) noexcept = default;
socket_address::socket_address(socket_address const &rhs) noexcept = default;

socket_address::socket_address(std::shared_ptr<socket_address_impl> impl) noexcept :
   m_impl{std::move(impl),}
{
   assert(nullptr != m_impl);
}

socket_address::operator std::string_view() const noexcept
{
   return m_impl->operator std::string_view();
}

socket_address::socket_address_impl const *socket_address::operator -> () const noexcept
{
   return m_impl.get();
}

socket_address &socket_address::operator = (socket_address &&rhs) noexcept = default;
socket_address &socket_address::operator = (socket_address const &rhs) = default;

std::ostream &operator << (std::ostream &sink, socket_address const &socketAddress)
{
   return sink << std::format("{}", socketAddress);
}

std::optional<socket_address> make_socket_address(std::string_view const &ipport, std::error_code &errorCode)
{
   if (auto const impl{socket_address::socket_address_impl::parse(ipport, 0, errorCode),}; nullptr != impl)
   {
      return socket_address{impl,};
   }
   assert(true == (bool{errorCode,}));
   return std::nullopt;
}

std::optional<socket_address> make_socket_address(std::string_view const &ip, uint16_t const port, std::error_code &errorCode)
{
   if (auto const impl{socket_address::socket_address_impl::parse(ip, port, errorCode),}; nullptr != impl)
   {
      return socket_address{impl,};
   }
   assert(true == (bool{errorCode,}));
   return std::nullopt;
}

}
