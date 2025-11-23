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

#include "common/logger.hpp" ///< for io_threads::log_error, io_threads::log_system_error
#include "common/utility.hpp" ///< for io_threads::to_underlying, io_threads::unreachable
#include "io_threads/socket_address.hpp" ///< for io_threads::socket_address
#include "linux/addrinfo_error.hpp" ///< for io_threads::make_addrinfo_error_code

#include <netdb.h> ///< for getnameinfo, NI_NUMERICHOST, NI_NUMERICSERV, NI_MAXHOST, NI_MAXSERV
#include <netinet/in.h> ///< for sockaddr_in, sockaddr_in6
#include <sys/socket.h> ///< for AF_INET, AF_INET6, AF_UNSPEC

#include <array> ///< for std::array
#include <cassert> ///< for assert
#include <cstdint> ///< for uint16_t
#include <cstring> ///< for std::memcpy
#include <memory> ///< for std::addressof, std::make_shared, std::shared_ptr
#include <source_location> ///< for std::source_location
#include <string> ///< for std::string
#include <string_view> ///< for std::string_view
#include <system_error> ///< for std::error_code, std::generic_category

namespace io_threads
{

struct sockaddr_inet final
{
   union
   {
      sa_family_t addressFamily;
      sockaddr ip;
      sockaddr_in ipv4;
      sockaddr_in6 ipv6;
   };
};

class socket_address::socket_address_impl final
{
public:
   socket_address_impl() = delete;
   socket_address_impl(socket_address_impl &&) = delete;
   socket_address_impl(socket_address_impl const &) = delete;

   [[nodiscard]] explicit socket_address_impl(sockaddr_in const &ipv4Address) :
      socket_address_impl{sockaddr_inet{.ipv4 = ipv4Address,}}
   {}

   [[nodiscard]] explicit socket_address_impl(sockaddr_in6 const &ipv6Address) :
      socket_address_impl{sockaddr_inet{.ipv6 = ipv6Address,}}
   {}

   [[nodiscard]] explicit socket_address_impl(sockaddr_inet const &address) :
      m_sockaddr{address}
   {
      std::array<char, NI_MAXHOST> addressHost{0,};
      std::array<char, NI_MAXSERV> addressPort{0,};
      if (
         auto const returnCode
         {
            getnameinfo(
               std::addressof(m_sockaddr.ip),
               (AF_INET == m_sockaddr.addressFamily) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6),
               addressHost.data(),
               addressHost.size(),
               addressPort.data(),
               addressPort.size(),
               NI_NUMERICHOST | NI_NUMERICSERV
            ),
         };
         0 != returnCode
      ) [[unlikely]]
      {
         log_system_error("[socket_address] failed to convert address to IP string: ({}) - {}", make_addrinfo_error_code(returnCode));
         unreachable();
      }
      assert(false == (std::string_view{addressHost.data(),}.empty()));
      assert(false == (std::string_view{addressPort.data(),}.empty()));
      if ((0 != addressPort[0]) && ('0' != addressPort[0]))
      {
         if (AF_INET6 == address.addressFamily)
         {
            m_address.assign("[").append(addressHost.data()).append("]");
         }
         else
         {
            m_address.assign(addressHost.data());
         }
         m_address.append(":").append(addressPort.data());
      }
      else
      {
         m_address.assign(addressHost.data());
      }
      m_address.shrink_to_fit();
   }

   [[nodiscard]] explicit operator std::string_view() const noexcept
   {
      return m_address;
   }

   socket_address_impl &operator = (socket_address_impl &&) = delete;
   socket_address_impl &operator = (socket_address_impl const &) = delete;

   [[nodiscard]] uint32_t family() const noexcept
   {
      return m_sockaddr.addressFamily;
   }

   [[nodiscard]] sockaddr_inet const &sockaddr() const noexcept
   {
      return m_sockaddr;
   }

   static std::shared_ptr<socket_address_impl> parse(std::string_view const &address, uint16_t const port, std::error_code &errorCode)
   {
      if (true == address.empty())
      {
         errorCode = std::make_error_code(std::errc::invalid_argument);
         return std::shared_ptr<socket_address_impl>{nullptr,};
      }
      sockaddr_inet socketAddress{.addressFamily = AF_UNSPEC,};
      if ('[' == address[0])
      {
         size_t const ipv6FirstSymbolIndex{1,};
         auto const ipv6LastSymbolIndex = address.find(']');
         if (std::string_view::npos == ipv6LastSymbolIndex)
         {
            errorCode = std::make_error_code(std::errc::invalid_argument);
            return std::shared_ptr<socket_address_impl>{nullptr,};
         }
         auto const ipv6Length{ipv6LastSymbolIndex - ipv6FirstSymbolIndex,};
         std::array<char, NI_MAXHOST> ipv6{0,};
         std::memcpy(ipv6.data(), address.data() + ipv6FirstSymbolIndex, ipv6Length);
         ipv6[ipv6Length] = 0;
         errorCode = std::error_code{};
         if (ipv6LastSymbolIndex < address.size())
         {
            auto const serviceFirstSymbolIndex = ipv6LastSymbolIndex + 2;
            if ((serviceFirstSymbolIndex < address.size()) && (':' == address[ipv6LastSymbolIndex + 1]))
            {
               std::array<char, NI_MAXSERV> service{0,};
               auto const serviceLength{address.size() - serviceFirstSymbolIndex,};
               std::memcpy(service.data(), address.data() + serviceFirstSymbolIndex, serviceLength);
               service[serviceLength] = 0;
               socketAddress = parse(AF_INET6, ipv6.data(), service.data(), errorCode);
            }
            else
            {
               errorCode = std::make_error_code(std::errc::invalid_argument);
               return std::shared_ptr<socket_address_impl>{nullptr,};
            }
         }
         else
         {
            socketAddress = parse(AF_INET6, ipv6.data(), nullptr, errorCode);
         }
      }
      else
      {
         std::array<char, NI_MAXHOST> ip{0,};
         std::memcpy(ip.data(), address.data(), address.size());
         ip[address.size()] = 0;
         errorCode = std::error_code{};
         socketAddress = parse(AF_INET6, ip.data(), nullptr, errorCode);
         if (AF_INET6 != socketAddress.addressFamily)
         {
            auto const ipv4LastSymbolIndex = address.find(':');
            errorCode = std::error_code{};
            if (std::string_view::npos == ipv4LastSymbolIndex)
            {
               socketAddress = parse(AF_INET, ip.data(), nullptr, errorCode);
            }
            else
            {
               ip[ipv4LastSymbolIndex] = 0;
               std::array<char, NI_MAXSERV> service{0,};
               auto const serviceLength{address.size() - ipv4LastSymbolIndex - 1,};
               std::memcpy(service.data(), address.data() + ipv4LastSymbolIndex + 1, serviceLength);
               service[serviceLength] = 0;
               socketAddress = parse(AF_INET, ip.data(), service.data(), errorCode);
            }
         }
      }
      if (AF_INET == socketAddress.addressFamily)
      {
         if (0 == socketAddress.ipv4.sin_port)
         {
            socketAddress.ipv4.sin_port = htons(port);
         }
         if (0 == socketAddress.ipv4.sin_port)
         {
            log_error(std::source_location::current(), "[socket_address:{}] port not specified", address);
         }
         return std::make_shared<socket_address_impl>(socketAddress);
      }
      else if (AF_INET6 == socketAddress.addressFamily)
      {
         if (0 == socketAddress.ipv6.sin6_port)
         {
            socketAddress.ipv6.sin6_port = htons(port);
         }
         if (0 == socketAddress.ipv6.sin6_port)
         {
            log_error(std::source_location::current(), "[socket_address:{}] port not specified", address);
         }
         return std::make_shared<socket_address_impl>(socketAddress);
      }
      assert(true == (bool{errorCode,}));
      return std::shared_ptr<socket_address_impl>{nullptr,};
   }

private:
   sockaddr_inet const m_sockaddr;
   std::string m_address{"",};

   static sockaddr_inet parse(
      sa_family_t const addressFamily,
      char const *ip,
      char const *service,
      std::error_code &errorCode
   )
   {
      addrinfo const addrHints
      {
         .ai_flags = AI_NUMERICHOST,
         .ai_family = addressFamily,
         .ai_socktype = SOCK_STREAM,
         .ai_protocol = IPPROTO_TCP,
         .ai_addrlen = 0,
         .ai_addr = nullptr,
         .ai_canonname = nullptr,
         .ai_next = nullptr,
      };
      addrinfo *parsedAddr{nullptr,};
      if (
         auto const returnCode{getaddrinfo(ip, service, std::addressof(addrHints), std::addressof(parsedAddr)),};
         0 != returnCode
      )
      {
         errorCode = make_addrinfo_error_code(returnCode);
         return sockaddr_inet{.addressFamily = AF_UNSPEC,};
      }
      assert(nullptr != parsedAddr);
      assert(SOCK_STREAM == parsedAddr->ai_socktype);
      assert(IPPROTO_TCP == parsedAddr->ai_protocol);
      assert(nullptr != parsedAddr->ai_addr);
      assert(addressFamily == parsedAddr->ai_addr->sa_family);
      assert(nullptr == parsedAddr->ai_next);
      sockaddr_inet const address
      {
         (AF_INET == parsedAddr->ai_addr->sa_family)
            ? sockaddr_inet{.ipv4 = *std::bit_cast<sockaddr_in const *>(parsedAddr->ai_addr),}
            : sockaddr_inet{.ipv6 = *std::bit_cast<sockaddr_in6 const *>(parsedAddr->ai_addr),}
         ,
      };
      freeaddrinfo(parsedAddr);
      return address;
   }
};

}
