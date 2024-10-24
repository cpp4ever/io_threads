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

#include <format> ///< for std::format, std::format_string, std::make_format_args, std::vformat
#include <iostream> ///< for std::cerr
#include <ostream> ///< for std::endl
#include <source_location> ///< for std::source_location
#include <string> ///< for std::string
#include <syncstream> ///< for std::osyncstream
#include <system_error> ///< for std::error_code
#include <type_traits> ///< for std::type_identity_t
#include <utility> ///< for std::forward

#if (202207L > __cpp_lib_format)
namespace std
{

template<typename ...types>
using format_string = std::string_view;

}
#endif

namespace io_threads
{

template<typename ...types>
constexpr void log_error(
   std::source_location const sourceLocation,
   std::format_string<std::type_identity_t<types>...> const fmt,
   types &&...values
)
{
   std::osyncstream{std::cerr}
      << sourceLocation.file_name() << ":" << sourceLocation.line() << " "
#if (202207L <= __cpp_lib_format)
      << std::format(fmt, std::forward<types>(values)...)
#else
      << std::vformat(fmt, std::make_format_args(std::forward<types>(values)...))
#endif
      << std::endl
   ;
}

inline void log_system_error(
   std::source_location const sourceLocation,
   std::format_string<int, std::string> const fmt,
   std::error_code const errorCode
)
{
   log_error(sourceLocation, fmt, errorCode.value(), errorCode.message());
}

inline void log_system_error(
   std::source_location const sourceLocation,
   std::format_string<int, std::string> const fmt,
   long const errorCode
)
{
   log_system_error(
      sourceLocation,
      fmt,
      std::error_code
      {
         static_cast<int>(errorCode),
         std::system_category(),
      }
   );
}

}
