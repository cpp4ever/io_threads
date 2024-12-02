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
#include "io_threads/network_interface.hpp" ///< for io_threads::network_interface
#include "io_threads/socket_address.hpp" ///< for io_threads::socket_address
#include "linux/socket_address_impl.hpp" ///< for io_threads::socket_address::socket_address_impl

#include <ifaddrs.h>

#include <cstddef> ///< for size_t, std::bit_cast
#include <memory> ///< for std::addressof, std::construct_at, std::destroy_at, std::make_shared, std::shared_ptr
#include <new> ///< for operator delete, operator new, std::align_val_t, std::launder
#include <optional> ///< for std::nullopt, std::optional
#include <source_location> ///< for std::source_location
#include <string> ///< for std::string, std::wstring
#include <string_view> ///< for std::string_view
#include <utility> ///< for std::move
#include <vector> ///< for std::vector

namespace io_threads
{

class network_interface::network_interface_impl final
{
public:
   network_interface_impl() = delete;
   network_interface_impl(network_interface_impl &&) = delete;
   network_interface_impl(network_interface_impl const &) = delete;

   [[nodiscard]] network_interface_impl(
      std::string &&systemName,
      std::string &&friendlyName,
      std::optional<socket_address> &&ipv4,
      std::optional<socket_address> &&ipv6,
      bool loopback
   ) :
      m_systemName{std::move(systemName)},
      m_friendlyName{std::move(friendlyName)},
      m_ipv4{std::move(ipv4)},
      m_ipv6{std::move(ipv6)},
      m_loopback{loopback}
   {}

   network_interface_impl &operator = (network_interface_impl &&) = delete;
   network_interface_impl &operator = (network_interface_impl const &) = delete;

   [[nodiscard]] std::string_view friendly_name() const noexcept
   {
      return m_friendlyName;
   }

   [[nodiscard]] std::optional<socket_address> const &ip_v4() const noexcept
   {
      return m_ipv4;
   }

   [[nodiscard]] std::optional<socket_address> const &ip_v6() const noexcept
   {
      return m_ipv6;
   }

   [[nodiscard]] bool is_loopback() const noexcept
   {
      return m_loopback;
   }

   [[nodiscard]] std::string_view system_name() const noexcept
   {
      return m_systemName;
   }

   static std::vector<std::shared_ptr<network_interface_impl>> active_network_interfaces()
   {
      std::vector<std::shared_ptr<network_interface_impl>> networkInterfaces{};
      return networkInterfaces;
   }

private:
   std::string const m_systemName;
   std::string const m_friendlyName;
   std::optional<socket_address> const m_ipv4;
   std::optional<socket_address> const m_ipv6;
   bool const m_loopback;
};

}
