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

#include "io_threads/network_interface.hpp" ///< for io_threads::network_interface
#include "io_threads/tcp_client_address.hpp" ///< for io_threads::tcp_client_address
#include "io_threads/socket_address.hpp" ///< for io_threads::socket_address
#include "io_threads/time.hpp" ///< for io_threads::steady_time, io_threads::time_duration
#include "io_threads/throttling_queue.hpp" ///< for io_threads::throttling_queue

#include <cstddef> ///< for size_t
#include <map> ///< for std::map
#include <memory> ///< for std::unique_ptr
#include <mutex> ///< for std::mutex
#include <optional> ///< for std::optional
#include <vector> ///< for std::vector

namespace io_threads
{

class connection_throttler final
{
public:
   connection_throttler() = delete;
   connection_throttler(connection_throttler &&) = delete;
   connection_throttler(connection_throttler const &) = delete;
   [[nodiscard]] connection_throttler(time_duration rollingTimeWindow, size_t quota);
   [[nodiscard]] connection_throttler(std::vector<network_interface> const &networkInterfaces, time_duration rollingTimeWindow, size_t quota);

   connection_throttler &operator = (connection_throttler &&) = delete;
   connection_throttler &operator = (connection_throttler const &) = delete;

   [[nodiscard]] steady_time enqueue(tcp_client_address const &tcpClientAddress, steady_time now);

private:
   time_duration const m_rollingTimeWindow;
   size_t const m_quota;
   class network_interface_throttling_queue final
   {
   public:
      network_interface_throttling_queue() = delete;
      network_interface_throttling_queue(network_interface_throttling_queue &&) = delete;
      network_interface_throttling_queue(network_interface_throttling_queue const &) = delete;
      [[nodiscard]] network_interface_throttling_queue(time_duration rollingTimeWindow, size_t quota);

      network_interface_throttling_queue &operator = (network_interface_throttling_queue &&) = delete;
      network_interface_throttling_queue &operator = (network_interface_throttling_queue const &) = delete;

      [[nodiscard]] steady_time enqueue(socket_address const &socketAddress, steady_time now);

   private:
      throttling_queue m_ipv4;
      throttling_queue m_ipv6;
   };
   struct network_interface_compare final
   {
      [[nodiscard]] bool operator() (std::optional<network_interface> const &lhs, std::optional<network_interface> const &rhs) const noexcept;
   };
   std::map<std::optional<network_interface>, network_interface_throttling_queue, network_interface_compare> m_mapNetworkInterfaceToThrottler{};
   std::mutex m_lock{};

   [[nodiscard]] network_interface_throttling_queue &find_or_create_throttler(std::optional<network_interface> const &networkInterface);
};

}
