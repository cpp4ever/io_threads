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

#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <cstdlib> ///< std::abort
#include <type_traits> ///< for std::is_enum_v, std::underlying_type_t
#include <utility> ///< for std::to_underlying, std::unreachable
#include <version> ///< for __cpp_lib_to_underlying, __cpp_lib_unreachable

namespace io_threads
{

#if (202102L <= __cpp_lib_to_underlying)
using to_underlying = std::to_underlying
#else
template<typename type> requires(true == std::is_enum_v<type>)
[[nodiscard]] constexpr std::underlying_type_t<type> to_underlying(type const value) noexcept
{
   return std::bit_cast<std::underlying_type_t<type>>(value);
}
#endif

[[noreturn]] inline void unreachable()
{
   assert(false && "It must be a bug");
#if (202202L <= __cpp_lib_unreachable)
   std::unreachable();
#else
   std::abort();
#endif
}

}
