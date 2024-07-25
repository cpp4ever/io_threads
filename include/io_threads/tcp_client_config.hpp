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
#include <io_threads/tcp_keep_alive.hpp> ///< for io_threads::tcp_keep_alive

#include <chrono> ///< for std::chrono::milliseconds
#include <optional> ///< for std::nullopt, std::optional
#include <utility> ///< for std::move

namespace io_threads
{

class tcp_client_config final
{
public:
   tcp_client_config() = delete;
   [[maybe_unused, nodiscard]] tcp_client_config(tcp_client_config &&) noexcept = default;
   [[maybe_unused, nodiscard]] tcp_client_config(tcp_client_config const &) noexcept = default;

   [[maybe_unused, nodiscard]] explicit tcp_client_config(tcp_client_address &&peerAddress) noexcept :
      m_peerAddress(std::move(peerAddress))
   {}

   [[maybe_unused, nodiscard]] explicit tcp_client_config(tcp_client_address const &peerAddress) noexcept :
      m_peerAddress(peerAddress)
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

   [[maybe_unused, nodiscard]] std::chrono::milliseconds user_timeout() const noexcept
   {
      return m_userTimeout;
   }

   [[maybe_unused, nodiscard]] tcp_client_config with_keep_alive(tcp_keep_alive const value) const noexcept
   {
      tcp_client_config config = *this;
      config.m_keepAlive = value;
      return config;
   }

   [[maybe_unused, nodiscard]] tcp_client_config with_nodelay() const noexcept
   {
      tcp_client_config config = *this;
      config.m_nodelay = true;
      return config;
   }

   [[maybe_unused, nodiscard]] tcp_client_config with_user_timeout(std::chrono::milliseconds const value) const noexcept
   {
      tcp_client_config config = *this;
      config.m_userTimeout = value;
      return config;
   }

private:
   std::optional<tcp_keep_alive> m_keepAlive = std::nullopt;
   bool m_nodelay = false;
   tcp_client_address m_peerAddress;
   std::chrono::milliseconds m_userTimeout = std::chrono::milliseconds::zero();
};

}
