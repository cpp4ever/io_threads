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

#include <cstdint> ///< for uint32_t
#include <format> ///< for std::format, std::format_string, std::make_format_args, std::vformat
#include <iostream> ///< for std::cerr
#include <ostream> ///< for std::endl
#include <source_location> ///< for std::source_location
#include <string> ///< for std::string
#include <string_view> ///< for std::string_view
#include <syncstream> ///< for std::osyncstream
#include <system_error> ///< for std::error_code, std::system_category
#include <utility> ///< for std::forward
#include <version> ///< for __cpp_lib_format

namespace io_threads
{

#if (202207L <= __cpp_lib_format)
template<typename ...types>
using format_string = std::format_string<types...>;
#else
template<typename ...types>
using format_string = std::string_view;
#endif

template<typename ...types>
constexpr void log_error(
   std::source_location const &sourceLocation,
   format_string<types...> const &fmt,
   types &&...values
)
{
   std::osyncstream{std::cerr,}
      << sourceLocation.file_name() << ":" << sourceLocation.line() << " "
#if (202207L <= __cpp_lib_format)
      << std::format(fmt, std::forward<types>(values)...)
#else
      << std::vformat(fmt, std::make_format_args(values...))
#endif
      << std::endl
   ;
}

inline void log_system_error(
   format_string<uint32_t, std::string> const &fmt,
   std::error_code const &errorCode,
   std::source_location const &sourceLocation = std::source_location::current()
)
{
   log_error(sourceLocation, fmt, static_cast<uint32_t>(errorCode.value()), errorCode.message());
}

inline void log_system_error(
   format_string<uint32_t, std::string> const &fmt,
   int const value,
   std::source_location const &sourceLocation = std::source_location::current()
)
{
   std::error_code const errorCode
   {
      value,
#if (defined(_WIN32) || defined(_WIN64))
      std::system_category(),
#else
      std::generic_category(),
#endif
   };
   log_system_error(fmt, errorCode, sourceLocation);
}

}
