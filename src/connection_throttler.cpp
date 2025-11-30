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

#include "io_threads/connection_throttler.hpp" ///< for io_threads::connection_throttler
#include "io_threads/network_interface.hpp" ///< for io_threads::network_interface
#include "io_threads/socket_address.hpp" ///< for io_threads::socket_address
#include "io_threads/tcp_client_address.hpp" ///< for io_threads::tcp_client_address
#include "io_threads/time.hpp" ///< for io_threads::steady_time, io_threads::time_duration
#include "io_threads/throttling_queue.hpp" ///< for io_threads::throttling_queue

#include <cassert> ///< for assert
#include <cstddef> ///< for size_t
#include <mutex> ///< for std::scoped_lock
#include <optional> ///< for std::nullopt, std::optional
#include <vector> ///< for std::vector

namespace io_threads
{

bool connection_throttler::network_interface_compare::operator() (
   std::optional<network_interface> const &lhs,
   std::optional<network_interface> const &rhs
) const noexcept
{
   if (auto const lhsHasValue{lhs.has_value(),}; (lhsHasValue != rhs.has_value()) || (false == lhsHasValue))
   {
      return lhsHasValue;
   }
   return lhs->system_name() < rhs->system_name();
}

connection_throttler::connection_throttler(time_duration const rollingTimeWindow, size_t const quota) :
   connection_throttler{std::vector<network_interface>{}, rollingTimeWindow, quota,}
{}

connection_throttler::connection_throttler(std::vector<network_interface> const &networkInterfaces, time_duration const rollingTimeWindow, size_t const quota) :
   m_rollingTimeWindow{rollingTimeWindow,},
   m_quota{quota,}
{
   assert(rollingTimeWindow > time_duration::zero());
   assert(quota > 0);
   if (true == networkInterfaces.empty())
   {
      m_mapNetworkInterfaceToThrottler.try_emplace(std::nullopt, m_rollingTimeWindow, m_quota);
   }
   else
   {
      for (auto const &networkInterface : networkInterfaces)
      {
         m_mapNetworkInterfaceToThrottler.try_emplace(networkInterface, m_rollingTimeWindow, m_quota);
      }
   }
}

steady_time connection_throttler::enqueue(tcp_client_address const &tcpClientAddress, steady_time const now)
{
   return find_or_create_throttler(tcpClientAddress.network_interface()).enqueue(tcpClientAddress.socket_address(), now);
}

connection_throttler::network_interface_throttling_queue::network_interface_throttling_queue(time_duration const rollingTimeWindow, size_t const quota) :
   m_ipv4{rollingTimeWindow, quota,},
   m_ipv6{rollingTimeWindow, quota,}
{}

steady_time connection_throttler::network_interface_throttling_queue::enqueue(socket_address const &socketAddress, steady_time const now)
{
   if (true == socketAddress.ipv4())
   {
      return m_ipv4.enqueue(now);
   }
   assert(true == socketAddress.ipv6());
   return m_ipv6.enqueue(now);
}

connection_throttler::network_interface_throttling_queue &connection_throttler::find_or_create_throttler(std::optional<network_interface> const &networkInterface)
{
   [[maybe_unused]] std::scoped_lock const throttlerGuard{m_lock,};
   return m_mapNetworkInterfaceToThrottler.try_emplace(networkInterface, m_rollingTimeWindow, m_quota).first->second;
}

}
