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
#include "windows/wide_char.hpp" ///< for io_threads::utf8_to_wide_char, io_threads::wide_char_to_utf8

#include <bcrypt.h> ///< for NTSTATUS
/// for
///   AF_INET,
///   AF_INET6,
///   BYTE,
///   DWORD,
///   ERROR_SUCCESS,
///   htons,
///   ParseNetworkString,
///   SOCKADDR_IN,
///   UCHAR,
///   ULONG,
///   USHORT
#include <WinSock2.h>
#include <WinDNS.h> ///< for ParseNetworkString
/// for
///   IN6ADDR_ISUNSPECIFIED,
///   INET_ADDRSTRLEN,
///   INET6_ADDRSTRLEN,
///   ParseNetworkString,
///   SOCKADDR_IN6,
///   SOCKADDR_INET
#include <ws2ipdef.h>
#include <ip2string.h> ///< for RtlIpv4AddressToStringExW, RtlIpv6AddressToStringExW
/// for
///   NET_ADDRESS_FORMAT,
///   NET_ADDRESS_INFO,
///   NET_STRING_IP_ADDRESS,
///   NET_STRING_IP_ADDRESS_NO_SCOPE,
///   NET_STRING_IP_SERVICE,
///   NET_STRING_IP_SERVICE_NO_SCOPE,
///   ParseNetworkString
#include <iphlpapi.h>
#include <mstcpip.h> ///< for IN4ADDR_ISUNSPECIFIED, Ipv4AddressType, NlatInvalid
#include <SubAuth.h> ///< for STATUS_SUCCESS

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

#pragma comment(lib, "iphlpapi")
#pragma comment(lib, "kernel32")
#pragma comment(lib, "ntdll")

namespace io_threads
{

class socket_address::socket_address_impl final
{
public:
   socket_address_impl() = delete;
   socket_address_impl(socket_address_impl &&) = delete;
   socket_address_impl(socket_address_impl const &) = delete;

   [[nodiscard]] explicit socket_address_impl(SOCKADDR_IN const &ipv4Address) :
      socket_address_impl{SOCKADDR_INET{.Ipv4 = ipv4Address,},}
   {}

   [[nodiscard]] explicit socket_address_impl(SOCKADDR_IN6 const &ipv6Address) :
      socket_address_impl{SOCKADDR_INET{.Ipv6 = ipv6Address,},}
   {}

   [[nodiscard]] explicit socket_address_impl(SOCKADDR_INET const &address) :
      m_sockaddr{address,}
   {
      std::wstring wcharAddress;
      if (AF_INET == m_sockaddr.si_family)
      {
         wcharAddress.resize(INET_ADDRSTRLEN * 2);
         auto wcharAddressSize{static_cast<ULONG>(wcharAddress.size()),};
         if (
            auto const ntstatus
            {
               RtlIpv4AddressToStringExW(
                  std::addressof(m_sockaddr.Ipv4.sin_addr),
                  m_sockaddr.Ipv4.sin_port,
                  wcharAddress.data(),
                  std::addressof(wcharAddressSize)
               ),
            };
            STATUS_SUCCESS != ntstatus
         )
         {
            log_system_error("[socket_address] failed to convert address to IPv4 string: ({}) - {}", ntstatus);
            unreachable();
         }
         wcharAddress.resize(std::max<size_t>(1, wcharAddressSize) - 1);
      }
      else if (AF_INET6 == m_sockaddr.si_family)
      {
         wcharAddress.resize(INET6_ADDRSTRLEN * 2);
         auto wcharAddressSize{static_cast<ULONG>(wcharAddress.size()),};
         if (
            auto const ntstatus
            {
               RtlIpv6AddressToStringExW(
                  std::addressof(m_sockaddr.Ipv6.sin6_addr),
                  m_sockaddr.Ipv6.sin6_scope_id,
                  m_sockaddr.Ipv6.sin6_port,
                  wcharAddress.data(),
                  std::addressof(wcharAddressSize)
               ),
            };
            STATUS_SUCCESS != ntstatus
         )
         {
            log_system_error("[socket_address] failed to convert address to IPv6 string: ({}) - {}", ntstatus);
            unreachable();
         }
         wcharAddress.resize(std::max<size_t>(1, wcharAddressSize) - 1);
      }
      else [[unlikely]]
      {
         log_error(std::source_location::current(), "[socket_address] unexpected address family: {}", m_sockaddr.si_family);
         unreachable();
      }
      if (auto const errorCode{wide_char_to_utf8(m_address, wcharAddress),}; true == bool{errorCode}) [[unlikely]]
      {
         log_system_error("[socket_address] failed to convert address to UTF-8 string: ({}) - {}", errorCode);
         unreachable();
      }
      m_address.shrink_to_fit();
   }

   [[nodiscard]] explicit operator std::string_view() const noexcept
   {
      return m_address;
   }

   socket_address_impl &operator = (socket_address_impl &&) = delete;
   socket_address_impl &operator = (socket_address_impl const &) = delete;

   [[nodiscard]] SOCKADDR_INET const &sockaddr() const noexcept
   {
      return m_sockaddr;
   }

   static std::shared_ptr<socket_address_impl> parse(std::string_view const &utf8Address, uint16_t const port, std::error_code &errorCode)
   {
      std::wstring wcharAddress;
      if (true == bool{(errorCode = utf8_to_wide_char(wcharAddress, utf8Address)),}) [[unlikely]]
      {
         log_system_error("[socket_address] failed to convert address to wchar_t string: ({}) - {}", errorCode);
         return std::shared_ptr<socket_address_impl>{nullptr,};
      }
      constexpr auto addressTypes
      {
         std::to_array<DWORD>(
            {
               NET_STRING_IP_ADDRESS,
               NET_STRING_IP_ADDRESS_NO_SCOPE,
               NET_STRING_IP_SERVICE,
               NET_STRING_IP_SERVICE_NO_SCOPE,
            }
         ),
      };
      for (auto const &addressType : addressTypes)
      {
         NET_ADDRESS_INFO netAddressInfo{};
         USHORT portNumber{0,};
         BYTE prefixLength{0,};
         if (
            auto const returnCode
            {
               ParseNetworkString(
                  wcharAddress.data(),
                  addressType,
                  std::addressof(netAddressInfo),
                  std::addressof(portNumber),
                  std::addressof(prefixLength)
               ),
            };
            ERROR_SUCCESS == returnCode
         )
         {
            errorCode = std::error_code{};
            switch (netAddressInfo.Format)
            {
            case NET_ADDRESS_FORMAT::NET_ADDRESS_IPV4:
            {
               assert(AF_INET == netAddressInfo.Ipv4Address.sin_family);
               assert(false == IN4ADDR_ISUNSPECIFIED(std::addressof(netAddressInfo.Ipv4Address)));
               assert(NlatInvalid != Ipv4AddressType(std::bit_cast<UCHAR *>(std::addressof(netAddressInfo.Ipv4Address.sin_addr))));
               if (0 < port)
               {
                  netAddressInfo.Ipv4Address.sin_port = htons(port);
               }
               if (0 == netAddressInfo.Ipv4Address.sin_port)
               {
                  log_error(std::source_location::current(), "[socket_address:{}] port not specified", utf8Address);
               }
            }
            return std::make_shared<socket_address_impl>(netAddressInfo.Ipv4Address);

            case NET_ADDRESS_FORMAT::NET_ADDRESS_IPV6:
            {
               assert(AF_INET6 == netAddressInfo.Ipv6Address.sin6_family);
               assert(false == IN6ADDR_ISUNSPECIFIED(std::addressof(netAddressInfo.Ipv6Address)));
               if (0 < port)
               {
                  netAddressInfo.Ipv6Address.sin6_port = htons(port);
               }
               if (0 == netAddressInfo.Ipv6Address.sin6_port)
               {
                  log_error(std::source_location::current(), "[socket_address:{}] port not specified", utf8Address);
               }
            }
            return std::make_shared<socket_address_impl>(netAddressInfo.Ipv6Address);

            default:
            {
               log_error(std::source_location::current(), "[socket_address:{}] unexpected format: {}", utf8Address, to_underlying(netAddressInfo.Format));
               unreachable();
            }
            break;
            }
         }
         else
         {
            errorCode = std::error_code{static_cast<int>(returnCode), std::system_category(),};
         }
      }
      return std::shared_ptr<socket_address_impl>{nullptr,};
   }

private:
   SOCKADDR_INET const m_sockaddr;
   std::string m_address{"",};
};

}
