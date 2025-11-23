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

#include <cassert> ///< for assert
#include <string_view> ///< for std::string_view

namespace io_threads
{

class websocket_client_config final
{
public:
   [[maybe_unused, nodiscard]] websocket_client_config() noexcept = default;
   [[maybe_unused, nodiscard]] websocket_client_config(websocket_client_config &&) noexcept = default;
   [[maybe_unused, nodiscard]] websocket_client_config(websocket_client_config const &) noexcept = default;

   [[maybe_unused, nodiscard]] explicit websocket_client_config(std::string_view const &target) noexcept :
      m_target{target}
   {
      assert(false == m_target.empty());
   }

   [[maybe_unused]] websocket_client_config &operator = (websocket_client_config &&) noexcept = default;
   [[maybe_unused]] websocket_client_config &operator = (websocket_client_config const &) noexcept = default;

   [[maybe_unused, nodiscard]] std::string_view const &target() const noexcept
   {
      return m_target;
   }

private:
   std::string_view m_target{"/",};
};

}
