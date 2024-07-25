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

#include <io_threads/tcp_client_address.hpp> ///< for io_threads::tcp_client_address

#include <cstdint> ///< for uint8_t
#include <chrono> ///< for std::chrono::milliseconds, std::chrono::seconds
#include <optional> ///< for std::nullopt, std::optional
#include <utility> ///< for std::move

namespace io_threads
{

struct tcp_keep_alive final
{
   std::chrono::seconds idleTimeout{std::chrono::seconds::zero()};
   std::chrono::seconds probeTimeout{std::chrono::seconds::zero()};
   uint8_t probesCount{0};
};

enum struct quality_of_service : uint8_t
{
   dscp_cs0  [[maybe_unused]] = 0x00,
   dscp_cs1  [[maybe_unused]] = 0x20,
   dscp_cs2  [[maybe_unused]] = 0x40,
   dscp_cs3  [[maybe_unused]] = 0x60,
   dscp_cs4  [[maybe_unused]] = 0x80,
   dscp_cs5  [[maybe_unused]] = 0xa0,
   dscp_cs6  [[maybe_unused]] = 0xc0,
   dscp_cs7  [[maybe_unused]] = 0xe0,
   dscp_af11 [[maybe_unused]] = 0x28,
   dcsp_af12 [[maybe_unused]] = 0x30,
   dscp_af13 [[maybe_unused]] = 0x38,
   dscp_af21 [[maybe_unused]] = 0x48,
   dscp_af22 [[maybe_unused]] = 0x50,
   dscp_af23 [[maybe_unused]] = 0x58,
   dscp_af31 [[maybe_unused]] = 0x68,
   dscp_af32 [[maybe_unused]] = 0x70,
   dscp_af33 [[maybe_unused]] = 0x78,
   dscp_af41 [[maybe_unused]] = 0x88,
   dscp_af42 [[maybe_unused]] = 0x90,
   dscp_af43 [[maybe_unused]] = 0x98,
   dscp_ef   [[maybe_unused]] = 0xb8,
};

class tcp_client_config final
{
public:
   tcp_client_config() = delete;
   [[maybe_unused, nodiscard]] tcp_client_config(tcp_client_config &&) noexcept = default;
   [[maybe_unused, nodiscard]] tcp_client_config(tcp_client_config const &) noexcept = default;

   [[maybe_unused, nodiscard]] explicit tcp_client_config(tcp_client_address &&peerAddress) noexcept :
      m_peerAddress{std::move(peerAddress)}
   {}

   [[maybe_unused, nodiscard]] explicit tcp_client_config(tcp_client_address const &peerAddress) noexcept :
      m_peerAddress{peerAddress}
   {}

   [[maybe_unused]] tcp_client_config &operator = (tcp_client_config &&) noexcept = default;
   [[maybe_unused]] tcp_client_config &operator = (tcp_client_config const &) noexcept = default;

   [[maybe_unused, nodiscard]] std::optional<tcp_keep_alive> const &keep_alive() const noexcept
   {
      return m_keepAlive;
   }

   [[maybe_unused, nodiscard]] bool nodelay() const noexcept
   {
      return m_nodelay;
   }

   [[maybe_unused, nodiscard]] tcp_client_address const &peer_address() const noexcept
   {
      return m_peerAddress;
   }

   [[maybe_unused, nodiscard]] io_threads::quality_of_service const &quality_of_service() const noexcept
   {
      return m_qualityOfService;
   }

   [[maybe_unused, nodiscard]] std::chrono::milliseconds user_timeout() const noexcept
   {
      return m_userTimeout;
   }

   [[maybe_unused, nodiscard]] tcp_client_config with_keep_alive(tcp_keep_alive const value) const noexcept
   {
      auto config{*this};
      config.m_keepAlive = value;
      return config;
   }

   [[maybe_unused, nodiscard]] tcp_client_config with_nodelay() const noexcept
   {
      auto config{*this};
      config.m_nodelay = true;
      return config;
   }

   [[maybe_unused, nodiscard]] tcp_client_config with_quality_of_service(io_threads::quality_of_service const value) const noexcept
   {
      auto config{*this};
      config.m_qualityOfService = value;
      return config;
   }

   [[maybe_unused, nodiscard]] tcp_client_config with_user_timeout(std::chrono::milliseconds const value) const noexcept
   {
      auto config{*this};
      config.m_userTimeout = value;
      return config;
   }

private:
   std::optional<tcp_keep_alive> m_keepAlive{std::nullopt};
   bool m_nodelay{false};
   io_threads::quality_of_service m_qualityOfService{io_threads::quality_of_service::dscp_cs0,};
   tcp_client_address m_peerAddress;
   std::chrono::milliseconds m_userTimeout{std::chrono::milliseconds::zero()};
};

}
