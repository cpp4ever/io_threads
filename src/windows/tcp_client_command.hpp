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

#include "utility.hpp" ///< for io_threads::to_underlying

#include <sdkddkver.h> ///< for _WIN32_WINNT
#include <Windows.h> ///< for LPOVERLAPPED

#include <bit> ///< for std::bit_cast
#include <cstdint> ///< for intptr_t

namespace io_threads
{

enum struct tcp_client_command : intptr_t
{
   unknown = 0,
   ready_to_connect,
   ready_to_disconnect,
   ready_to_send,
};

[[nodiscard]] constexpr tcp_client_command from_completion_overlapped(LPOVERLAPPED const overlapped) noexcept
{
   return tcp_client_command{std::bit_cast<intptr_t>(overlapped)};
}

[[nodiscard]] constexpr LPOVERLAPPED to_completion_overlapped(tcp_client_command const value) noexcept
{
   return std::bit_cast<LPOVERLAPPED>(to_underlying(value));
}

}
