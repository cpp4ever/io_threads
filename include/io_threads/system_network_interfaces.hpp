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

#include <map> ///< for std::map
#include <optional> ///< for std::nullopt, std::optional
#include <string_view> ///< for std::string_view

namespace io_threads
{

class network_interface::system_network_interfaces final
{
private:
   using map_string_to_network_interface = std::map<std::string_view, network_interface>;

public:
   [[nodiscard]] system_network_interfaces();
   [[maybe_unused, nodiscard]] system_network_interfaces(system_network_interfaces &&rhs) noexcept = default;
   [[maybe_unused, nodiscard]] system_network_interfaces(system_network_interfaces const &rhs) = default;
   [[maybe_unused]] ~system_network_interfaces() = default;

   [[maybe_unused]] system_network_interfaces &operator = (system_network_interfaces &&rhs) noexcept = default;
   [[maybe_unused]] system_network_interfaces &operator = (system_network_interfaces const &rhs) = delete;

   [[maybe_unused, nodiscard]] std::optional<network_interface> find(std::string_view const &interfaceNameOrIp) const
   {
      if (
         auto const interfaceIterator{m_mapStringToNetworkInterface.find(interfaceNameOrIp)};
         m_mapStringToNetworkInterface.end() != interfaceIterator
      )
      {
         return interfaceIterator->second;
      }
      return std::nullopt;
   }

   [[maybe_unused, nodiscard]] std::optional<network_interface> const &loopback() const noexcept
   {
      return m_loopbackNetworkInterface;
   }

private:
   map_string_to_network_interface m_mapStringToNetworkInterface{};
   std::optional<network_interface> m_loopbackNetworkInterface{std::nullopt};
};

using system_network_interfaces [[maybe_unused]] = network_interface::system_network_interfaces;

}
