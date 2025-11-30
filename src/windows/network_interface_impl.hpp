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
#include "io_threads/network_interface.hpp" ///< for io_threads::network_interface
#include "io_threads/socket_address.hpp" ///< for io_threads::socket_address
#include "windows/socket_address_impl.hpp" ///< for io_threads::socket_address::socket_address_impl
#include "windows/wide_char.hpp" ///< for io_threads::wide_char_to_utf8

/// for
///   ADDRESS_FAMILY,
///   AF_INET,
///   AF_INET6,
///   AF_UNSPEC,
///   CopyMemory,
///   ERROR_BUFFER_OVERFLOW,
///   ERROR_NOT_ENOUGH_MEMORY,
///   ERROR_SUCCESS,
///   ULONG
#include <WinSock2.h>
/// for
///   GetAdaptersAddresses,
///   IfOperStatusUp,
///   IP_ADAPTER_ADDRESSES,
///   IP_ADAPTER_IPV4_ENABLED,
///   IP_ADAPTER_IPV6_ENABLED,
///   IP_ADAPTER_RECEIVE_ONLY,
///   IF_TYPE_SOFTWARE_LOOPBACK,
///   IpDadStatePreferred
#include <iphlpapi.h>
#include <ws2ipdef.h> ///< for SOCKADDR_INET

#include <bit> ///< for std::bit_cast
#include <cstddef> ///< for size_t
#include <memory> ///< for std::addressof, std::construct_at, std::destroy_at, std::make_shared, std::shared_ptr
#include <new> ///< for operator delete, operator new, std::align_val_t
#include <optional> ///< for std::nullopt, std::optional
#include <string> ///< for std::string, std::wstring
#include <string_view> ///< for std::string_view
#include <utility> ///< for std::move
#include <vector> ///< for std::vector

#pragma comment(lib, "iphlpapi")

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
      bool const loopback
   ) :
      m_systemName{std::move(systemName)},
      m_friendlyName{std::move(friendlyName)},
      m_ipv4{std::move(ipv4)},
      m_ipv6{std::move(ipv6)},
      m_loopback{loopback}
   {}

   network_interface_impl &operator = (network_interface_impl &&) = delete;
   network_interface_impl &operator = (network_interface_impl const &) = delete;

   [[nodiscard]] std::string const &friendly_name() const noexcept
   {
      return m_friendlyName;
   }

   [[nodiscard]] std::optional<socket_address> const &ipv4() const noexcept
   {
      return m_ipv4;
   }

   [[nodiscard]] std::optional<socket_address> const &ipv6() const noexcept
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
      ULONG ipAdapterAddresesSize{1024 * 64};
      auto *ipAdapterAddreses
      {
         std::construct_at<IP_ADAPTER_ADDRESSES>(
            std::bit_cast<IP_ADAPTER_ADDRESSES *>(
               ::operator new(ipAdapterAddresesSize, std::align_val_t{alignof(IP_ADAPTER_ADDRESSES)})
            )
         ),
      };
      auto returnCode{GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, ipAdapterAddreses, std::addressof(ipAdapterAddresesSize))};
      if ((ERROR_BUFFER_OVERFLOW == returnCode) || (ERROR_NOT_ENOUGH_MEMORY == returnCode))
      {
         std::destroy_at(ipAdapterAddreses);
         ::operator delete(ipAdapterAddreses, std::align_val_t{alignof(IP_ADAPTER_ADDRESSES)});
         ipAdapterAddreses = std::construct_at<IP_ADAPTER_ADDRESSES>(
            std::bit_cast<IP_ADAPTER_ADDRESSES *>(
               ::operator new(ipAdapterAddresesSize, std::align_val_t{alignof(IP_ADAPTER_ADDRESSES)})
            )
         );
         returnCode = GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, ipAdapterAddreses, std::addressof(ipAdapterAddresesSize));
      }
      std::vector<std::shared_ptr<network_interface_impl>> networkInterfaces{};
      if (ERROR_SUCCESS == returnCode) [[likely]]
      {
         for (
            auto const *ipAdapterAddress{ipAdapterAddreses};
            nullptr != ipAdapterAddress;
            ipAdapterAddress = ipAdapterAddress->Next
         )
         {
            if (IP_ADAPTER_RECEIVE_ONLY == (IP_ADAPTER_RECEIVE_ONLY & ipAdapterAddress->Flags))
            {
               continue;
            }
            if (IfOperStatusUp != ipAdapterAddress->OperStatus)
            {
               continue;
            }
            networkInterfaces.push_back(create_network_interface(*ipAdapterAddress));
         }
      }
      else
      {
         log_system_error("[network_interface] failed to get adapters addresses: ({}) - {}", returnCode);
      }
      std::destroy_at(ipAdapterAddreses);
      ::operator delete(ipAdapterAddreses, std::align_val_t{alignof(IP_ADAPTER_ADDRESSES)});
      return networkInterfaces;
   }

private:
   std::string const m_systemName;
   std::string const m_friendlyName;
   std::optional<socket_address> const m_ipv4;
   std::optional<socket_address> const m_ipv6;
   bool const m_loopback;

   [[nodiscard]] static std::shared_ptr<network_interface_impl> create_network_interface(
      IP_ADAPTER_ADDRESSES const &ipAdapterAddress
   )
   {
      std::string systemName{ipAdapterAddress.AdapterName};
      systemName.shrink_to_fit();
      std::string friendlyName;
      if (
         auto const errorCode{wide_char_to_utf8(friendlyName, std::wstring{ipAdapterAddress.FriendlyName})};
         true == bool{errorCode}
      ) [[unlikely]]
      {
         log_system_error("[network_interface] failed to convert friendly name to UTF-8: ({}) - {}", errorCode);
      }
      friendlyName.shrink_to_fit();
      auto ipv4
      {
         (IP_ADAPTER_IPV4_ENABLED == (IP_ADAPTER_IPV4_ENABLED & ipAdapterAddress.Flags))
            ? create_socket_address(ipAdapterAddress, AF_INET)
            : std::nullopt
      };
      auto ipv6
      {
         (IP_ADAPTER_IPV6_ENABLED == (IP_ADAPTER_IPV6_ENABLED & ipAdapterAddress.Flags))
            ? create_socket_address(ipAdapterAddress, AF_INET6)
            : std::nullopt
      };
      return std::make_shared<network_interface_impl>(
         std::move(systemName),
         std::move(friendlyName),
         std::move(ipv4),
         std::move(ipv6),
         IF_TYPE_SOFTWARE_LOOPBACK == ipAdapterAddress.IfType
      );
   }

   [[nodiscard]] static std::optional<socket_address> create_socket_address(
      IP_ADAPTER_ADDRESSES const &ipAdapterAddress,
      ADDRESS_FAMILY const addressFamily
   )
   {
      for (
         auto const *unicastAddress{ipAdapterAddress.FirstUnicastAddress};
         nullptr != unicastAddress;
         unicastAddress = unicastAddress->Next
      )
      {
         if (
            (IpDadStatePreferred == unicastAddress->DadState) &&
            (addressFamily == unicastAddress->Address.lpSockaddr->sa_family)
         )
         {
            SOCKADDR_INET address{};
            CopyMemory(
               std::addressof(address),
               unicastAddress->Address.lpSockaddr,
               static_cast<size_t>(unicastAddress->Address.iSockaddrLength)
            );
            return socket_address{std::make_shared<socket_address::socket_address_impl>(address)};
         }
      }
      return std::nullopt;
   }
};

}
