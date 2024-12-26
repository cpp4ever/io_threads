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
#include <net/if.h> ///< for IFF_LOOPBACK

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
private:
   struct network_interface_addresses final
   {
      std::optional<socket_address> ipv4{std::nullopt,};
      std::optional<socket_address> ipv6{std::nullopt,};
      bool const loopback{false,};
   };

public:
   network_interface_impl() = delete;
   network_interface_impl(network_interface_impl &&) = delete;
   network_interface_impl(network_interface_impl const &) = delete;

   [[nodiscard]] network_interface_impl(
      std::string &&systemName,
      std::optional<socket_address> &&ipv4,
      std::optional<socket_address> &&ipv6,
      bool loopback
   ) :
      m_systemName{std::move(systemName)},
      m_ipv4{std::move(ipv4)},
      m_ipv6{std::move(ipv6)},
      m_loopback{loopback}
   {}

   network_interface_impl &operator = (network_interface_impl &&) = delete;
   network_interface_impl &operator = (network_interface_impl const &) = delete;

   [[nodiscard]] std::string const &friendly_name() const noexcept
   {
      return m_systemName;
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

   [[nodiscard]] std::string const &system_name() const noexcept
   {
      return m_systemName;
   }

   static std::vector<std::shared_ptr<network_interface_impl>> active_network_interfaces()
   {
      ifaddrs *ifaces{nullptr,};
      if (-1 == getifaddrs(std::addressof(ifaces))) [[unlikely]]
      {
         log_system_error("[network_interface] failed to get network interfaces: ({}) - {}", errno);
         unreachable();
      }
      std::map<std::string_view, network_interface_addresses> mapIfaceNameToAddress{};
      auto const getOrCreateAddress = [&mapIfaceNameToAddress] (ifaddrs const &iface) -> network_interface_addresses &
      {
         std::string_view const ifaceName{iface.ifa_name,};
         auto const isLoopback{(IFF_LOOPBACK == (iface.ifa_flags & IFF_LOOPBACK)),};
         if (
            auto const ifaceNameToAddress = mapIfaceNameToAddress.find(ifaceName);
            mapIfaceNameToAddress.end() != ifaceNameToAddress
         )
         {
            if (isLoopback != ifaceNameToAddress->second.loopback) [[unlikely]]
            {
               log_error(std::source_location::current(), "[network_interface] loopback and non-loopback addresses within the same network interface");
               unreachable();
            }
            return ifaceNameToAddress->second;
         }
         return mapIfaceNameToAddress.emplace(
            ifaceName,
            network_interface_addresses{.loopback = isLoopback,}
         ).first->second;
      };
      for (ifaddrs const *iface = ifaces; nullptr != iface; iface = iface->ifa_next)
      {
         if (
            false
            || (nullptr == iface->ifa_addr)
            || (IFF_RUNNING != (iface->ifa_flags & IFF_RUNNING))
         )
         {
            continue;
         }
         if (AF_INET == iface->ifa_addr->sa_family)
         {
            auto &ifaceAddress = getOrCreateAddress(*iface);
            if (false == ifaceAddress.ipv4.has_value())
            {
               ifaceAddress.ipv4.emplace(std::make_shared<socket_address::socket_address_impl>(*std::bit_cast<sockaddr_in *>(iface->ifa_addr)));
            }
         }
         else if (AF_INET6 == iface->ifa_addr->sa_family)
         {
            auto &ifaceAddress = getOrCreateAddress(*iface);
            if (false == ifaceAddress.ipv6.has_value())
            {
               ifaceAddress.ipv6.emplace(std::make_shared<socket_address::socket_address_impl>(*std::bit_cast<sockaddr_in6 *>(iface->ifa_addr)));
            }
         }
      }
      std::vector<std::shared_ptr<network_interface_impl>> networkInterfaces{};
      for (auto [ifaceName, ifaceAddress] : mapIfaceNameToAddress)
      {
         networkInterfaces.emplace_back(
            std::make_shared<network_interface_impl>(
               std::string{ifaceName,},
               std::move(ifaceAddress.ipv4),
               std::move(ifaceAddress.ipv6),
               ifaceAddress.loopback
            )
         );
      }
      freeifaddrs(ifaces);
      return networkInterfaces;
   }

private:
   std::string const m_systemName;
   std::optional<socket_address> const m_ipv4;
   std::optional<socket_address> const m_ipv6;
   bool const m_loopback;
};

}
