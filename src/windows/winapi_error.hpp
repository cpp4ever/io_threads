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

#include "common/logger.hpp" ///< for io_threads::format_string, io_threads::log_system_error

#include <Windows.h> ///< for DWORD, ERROR_SUCCESS, GetLastError

#include <cassert> ///< for assert
#include <cstdint> ///< for uint32_t
#include <source_location> ///< for std::source_location
#include <string> ///< for std::string
#include <system_error> ///< for std::error_code, std::system_category

#pragma comment(lib, "kernel32")

namespace io_threads
{

inline std::error_code check_winapi_error(
   format_string<uint32_t, std::string> const &fmt,
   std::source_location const &sourceLocation = std::source_location::current()
)
{
   auto const winapiLastError{GetLastError(),};
   assert(ERROR_SUCCESS != winapiLastError);
   std::error_code const errorCode{static_cast<int>(winapiLastError), std::system_category(),};
   assert(winapiLastError == static_cast<DWORD>(errorCode.value()));
   log_system_error(fmt, errorCode, sourceLocation);
   return errorCode;
}

inline std::error_code check_winapi_error_if_not(
   format_string<uint32_t, std::string> const &fmt,
   DWORD const expectedErrorCode,
   std::source_location const &sourceLocation = std::source_location::current()
)
{
   auto const winapiLastError{GetLastError(),};
   assert(ERROR_SUCCESS != winapiLastError);
   if (winapiLastError != expectedErrorCode) [[unlikely]]
   {
      std::error_code const errorCode{static_cast<int>(winapiLastError), std::system_category(),};
      assert(winapiLastError == static_cast<DWORD>(errorCode.value()));
      log_system_error(fmt, errorCode, sourceLocation);
      return errorCode;
   }
   return std::error_code{};
}

}
