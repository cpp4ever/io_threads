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

#include <io_threads/network_interface.hpp> ///< for io_threads::network_interface
#include <io_threads/socket_address.hpp> ///< for io_threads::socket_address

#include <optional> ///< for std::nullopt, std::optional
#include <utility> ///< for std::move

namespace io_threads
{

class tcp_client_address final
{
public:
   tcp_client_address() = delete;
   [[maybe_unused, nodiscard]] tcp_client_address(tcp_client_address &&) noexcept = default;
   [[maybe_unused, nodiscard]] tcp_client_address(tcp_client_address const &) noexcept = default;

   [[maybe_unused, nodiscard]] explicit tcp_client_address(io_threads::socket_address socketAddress) noexcept :
      m_networkInterface{std::nullopt,},
      m_socketAddress{std::move(socketAddress),}
   {}

   [[maybe_unused, nodiscard]] tcp_client_address(io_threads::network_interface networkInterface, io_threads::socket_address socketAddress) noexcept :
      m_networkInterface{std::move(networkInterface),},
      m_socketAddress{std::move(socketAddress),}
   {}

   [[maybe_unused]] tcp_client_address &operator = (tcp_client_address &&) noexcept = default;
   [[maybe_unused]] tcp_client_address &operator = (tcp_client_address const &) noexcept = default;

   [[maybe_unused, nodiscard]] std::optional<io_threads::network_interface> const &network_interface() const noexcept
   {
      return m_networkInterface;
   }

   [[maybe_unused, nodiscard]] io_threads::socket_address const &socket_address() const noexcept
   {
      return m_socketAddress;
   }

private:
   std::optional<io_threads::network_interface> m_networkInterface;
   io_threads::socket_address m_socketAddress;
};

}
