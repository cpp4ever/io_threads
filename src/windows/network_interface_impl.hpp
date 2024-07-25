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

#include "common/logger.hpp"
#include "io_threads/network_interface.hpp" ///< for io_threads::network_interface
#include "io_threads/socket_address.hpp" ///< for io_threads::socket_address
#include "windows/socket_address_impl.hpp"

#include <WinSock2.h>
#include <iphlpapi.h>
#include <ws2ipdef.h>

#include <memory> ///< for std::shared_ptr
#include <optional> ///< for std::optional
#include <string_view> ///< for std::string_view
#include <vector> ///< for std::vector

#pragma comment(lib, "iphlpapi.lib")

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
      m_systemName(std::move(systemName)),
      m_friendlyName(std::move(friendlyName)),
      m_ipv4(std::move(ipv4)),
      m_ipv6(std::move(ipv6)),
      m_loopback(loopback)
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
      ULONG adapterAddresesSize = 1024 * 64;
      auto *adapterAddresesMemory = ::operator new(adapterAddresesSize, std::align_val_t{alignof(IP_ADAPTER_ADDRESSES)});
      auto *adapterAddreses = new(adapterAddresesMemory) IP_ADAPTER_ADDRESSES{};
      auto returnCode = GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, adapterAddreses, std::addressof(adapterAddresesSize));
      if ((ERROR_BUFFER_OVERFLOW == returnCode) || (ERROR_NOT_ENOUGH_MEMORY == returnCode))
      {
         adapterAddreses->~IP_ADAPTER_ADDRESSES();
         ::operator delete(adapterAddresesMemory, std::align_val_t{alignof(IP_ADAPTER_ADDRESSES)});
         adapterAddresesMemory = ::operator new(adapterAddresesSize, std::align_val_t{alignof(IP_ADAPTER_ADDRESSES)});
         adapterAddreses = new(adapterAddresesMemory) IP_ADAPTER_ADDRESSES{};
         returnCode = GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, adapterAddreses, std::addressof(adapterAddresesSize));
      }
      std::vector<std::shared_ptr<network_interface_impl>> networkInterfaces = {};
      if (ERROR_SUCCESS == returnCode) [[likely]]
      {
         for (auto const *adapterAddress = adapterAddreses; nullptr != adapterAddress; adapterAddress = adapterAddress->Next)
         {
            if (IP_ADAPTER_RECEIVE_ONLY == (IP_ADAPTER_RECEIVE_ONLY & adapterAddress->Flags))
            {
               continue;
            }
            if (IfOperStatusUp != adapterAddress->OperStatus)
            {
               continue;
            }
            std::string systemName{adapterAddress->AdapterName};
            systemName.shrink_to_fit();
            std::wstring wcharFriendlyName{adapterAddress->FriendlyName};
            std::string utf8FriendlyName;
            utf8FriendlyName.resize(wcharFriendlyName.size() * 2);
            auto const utf8FriendlyNameSize = WideCharToMultiByte(
               CP_UTF8,
               WC_ERR_INVALID_CHARS,
               wcharFriendlyName.data(),
               static_cast<int>(wcharFriendlyName.size()),
               utf8FriendlyName.data(),
               static_cast<int>(utf8FriendlyName.size()),
               nullptr,
               nullptr
            );
            if (0 >= utf8FriendlyNameSize) [[unlikely]]
            {
               check_winapi_error("[network_interface] failed to convert friendly name to UTF-8: ({}) - {}");
            }
            assert(static_cast<size_t>(utf8FriendlyNameSize) <= utf8FriendlyName.size());
            utf8FriendlyName.resize(static_cast<size_t>(utf8FriendlyNameSize));
            utf8FriendlyName.shrink_to_fit();
            std::optional<socket_address> ipv4 = {};
            std::optional<socket_address> ipv6 = {};
            for (auto const *unicastAddress = adapterAddress->FirstUnicastAddress; nullptr != unicastAddress; unicastAddress = unicastAddress->Next)
            {
               if (IpDadStatePreferred == unicastAddress->DadState)
               {
                  if (
                     (AF_INET == unicastAddress->Address.lpSockaddr->sa_family) &&
                     (IP_ADAPTER_IPV4_ENABLED == (IP_ADAPTER_IPV4_ENABLED & adapterAddress->Flags))
                  )
                  {
                     auto socketAddress = std::make_shared<socket_address::socket_address_impl>(
                        *std::bit_cast<SOCKADDR_IN *>(unicastAddress->Address.lpSockaddr)
                     );
                     if (false == ipv4.has_value()) [[likely]]
                     {
                        ipv4 = socket_address{socketAddress};
                     }
                     else
                     {
                        log_error(
                           std::source_location::current(),
                           R"raw([network_interface:{}] has multiple preferred IPv4 addresses: {} and {})raw",
                           utf8FriendlyName,
                           std::string_view{ipv4.value()},
                           std::string_view{*socketAddress}
                        );
                     }
                  }
                  else if (
                     (AF_INET6 == unicastAddress->Address.lpSockaddr->sa_family) &&
                     (IP_ADAPTER_IPV6_ENABLED == (IP_ADAPTER_IPV6_ENABLED & adapterAddress->Flags))
                  )
                  {
                     auto socketAddress = std::make_shared<socket_address::socket_address_impl>(
                        *std::bit_cast<SOCKADDR_IN6 *>(unicastAddress->Address.lpSockaddr)
                     );
                     if (false == ipv6.has_value()) [[likely]]
                     {
                        ipv6 = socket_address{socketAddress};
                     }
                     else
                     {
                        log_error(
                           std::source_location::current(),
                           R"raw([network_interface:{}] has multiple preferred IPv6 addresses: {} and {})raw",
                           utf8FriendlyName,
                           std::string_view{ipv6.value()},
                           std::string{*socketAddress}
                        );
                     }
                  }
               }
            }
            networkInterfaces.push_back(
               std::make_shared<network_interface_impl>(
                  std::move(systemName),
                  std::move(utf8FriendlyName),
                  std::move(ipv4),
                  std::move(ipv6),
                  IF_TYPE_SOFTWARE_LOOPBACK == adapterAddress->IfType
               )
            );
         }
      }
      else
      {
         log_system_error(
            std::source_location::current(),
            "[network_interface] failed to get adapters addresses: ({}) - {}",
            returnCode
         );
      }
      adapterAddreses->~IP_ADAPTER_ADDRESSES();
      ::operator delete(adapterAddresesMemory, std::align_val_t{alignof(IP_ADAPTER_ADDRESSES)});
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
