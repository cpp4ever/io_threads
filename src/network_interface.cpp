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

#include "io_threads/network_interface.hpp" ///< for io_threads::network_interface
#include "io_threads/socket_address.hpp" ///< for io_threads::socket_address
#include "io_threads/system_network_interfaces.hpp" ///< for io_threads::system_network_interfaces
#if (defined(__linux__))
#  include "linux/network_interface_impl.hpp" ///< for io_threads::network_interface::network_interface_impl
#elif (defined(_WIN32) || defined(_WIN64))
#  include "windows/network_interface_impl.hpp" ///< for io_threads::network_interface::network_interface_impl
#endif

#include <cassert> ///< for assert
#include <format> ///< for std::format
#include <memory> ///< for std::shared_ptr
#include <optional> ///< for std::optional
#include <ostream> ///< for std::ostream
#include <string_view> ///< for std::string_view
#include <utility> ///< for std::move

namespace io_threads
{

network_interface::network_interface(network_interface &&rhs) noexcept = default;
network_interface::network_interface(network_interface const &rhs) noexcept = default;
network_interface::~network_interface() = default;

network_interface &network_interface::operator = (network_interface &&rhs) noexcept = default;
network_interface &network_interface::operator = (network_interface const &rhs) = default;

std::string_view network_interface::friendly_name() const noexcept
{
   return m_impl->friendly_name();
}

std::optional<socket_address> const &network_interface::ip_v4() const noexcept
{
   return m_impl->ip_v4();
}

std::optional<socket_address> const &network_interface::ip_v6() const noexcept
{
   return m_impl->ip_v6();
}

bool network_interface::is_loopback() const noexcept
{
   return m_impl->is_loopback();
}

std::string_view network_interface::system_name() const noexcept
{
   return m_impl->system_name();
}

network_interface::network_interface(std::shared_ptr<network_interface_impl> impl) noexcept :
   m_impl{std::move(impl),}
{
   assert(nullptr != m_impl);
}

network_interface::system_network_interfaces::system_network_interfaces()
{
   for (auto const &networkInterfaceImpl : network_interface_impl::active_network_interfaces())
   {
      network_interface networkInterface{networkInterfaceImpl,};
      m_mapStringToNetworkInterface.emplace(networkInterface.system_name(), networkInterface);
      auto const &ipv4{networkInterface.ip_v4(),};
      if (true == ipv4.has_value())
      {
         m_mapStringToNetworkInterface.emplace(ipv4.value(), networkInterface);
      }
      auto const &ipv6{networkInterface.ip_v6(),};
      if (true == ipv6.has_value())
      {
         m_mapStringToNetworkInterface.emplace(ipv6.value(), networkInterface);
      }
      if (true == networkInterface.is_loopback())
      {
         assert(false == m_loopbackNetworkInterface.has_value());
         m_loopbackNetworkInterface.emplace(networkInterface);
      }
   }
}

std::ostream &operator << (std::ostream &sink, network_interface const &networkInterface)
{
   return sink << std::format("{}", networkInterface);
}

}
