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

#include "common/logger.hpp" ///< for io_threads::format_string, io_threads::log_system_error

#include <WinSock2.h> ///< for ERROR_SUCCESS, WSAGetLastError

#include <cassert> ///< for assert
#include <cstdint> ///< for uint32_t
#include <source_location> ///< for std::source_location
#include <string> ///< for std::string
#include <system_error> ///< for std::error_code, std::system_category

#pragma comment(lib, "WS2_32")

namespace io_threads
{

std::error_code check_winsock_error(
   format_string<uint32_t, std::string> const &fmt,
   std::source_location const &sourceLocation = std::source_location::current()
)
{
   auto const winsockLastError{WSAGetLastError()};
   assert(ERROR_SUCCESS != winsockLastError);
   std::error_code const errorCode{winsockLastError, std::system_category()};
   assert(winsockLastError == errorCode.value());
   log_system_error(fmt, errorCode, sourceLocation);
   return errorCode;
}

std::error_code check_winsock_error_if_not(
   format_string<uint32_t, std::string> const &fmt,
   int const expectedErrorCode,
   std::source_location const &sourceLocation = std::source_location::current()
)
{
   auto const winsockLastError{WSAGetLastError()};
   assert(ERROR_SUCCESS != winsockLastError);
   if (winsockLastError != expectedErrorCode) [[unlikely]]
   {
      std::error_code const errorCode{winsockLastError, std::system_category()};
      assert(winsockLastError == errorCode.value());
      log_system_error(fmt, errorCode, sourceLocation);
      return errorCode;
   }
   return std::error_code{};
}

}
