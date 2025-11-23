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

/// for
///   CP_UTF8,
///   GetLastError,
///   MB_ERR_INVALID_CHARS,
///   MultiByteToWideChar,
///   WC_ERR_INVALID_CHARS,
///   WideCharToMultiByte
#include <Windows.h>

#include <cassert> ///< for assert
#include <cstddef> ///< for size_t
#include <string> ///< for std::string, std::wstring
#include <string_view> ///< for std::string_view, std::wstring_view
#include <system_error> ///< for std::error_code, std::system_category

#pragma comment(lib, "kernel32")

namespace io_threads
{

[[nodiscard]] inline std::error_code utf8_to_wide_char(
   std::wstring &wideCharString,
   std::string_view const &utf8String
)
{
   wideCharString.clear();
   wideCharString.resize(utf8String.size() * 2);
   auto const wideCharStringSize
   {
      MultiByteToWideChar(
         CP_UTF8,
         MB_ERR_INVALID_CHARS,
         utf8String.data(),
         static_cast<int>(utf8String.size()),
         wideCharString.data(),
         static_cast<int>(wideCharString.size())
      )
   };
   if (0 >= wideCharStringSize) [[unlikely]]
   {
      wideCharString.resize(0);
      return std::error_code{static_cast<int>(GetLastError()), std::system_category(),};
   }
   assert(static_cast<size_t>(wideCharStringSize) <= wideCharString.size());
   wideCharString.resize(static_cast<size_t>(wideCharStringSize));
   return std::error_code{};
}

[[nodiscard]] inline std::error_code wide_char_to_utf8(
   std::string &utf8String,
   std::wstring_view const &wideCharString
)
{
   utf8String.clear();
   utf8String.resize(wideCharString.size() * 2);
   auto const utf8StringSize
   {
      WideCharToMultiByte(
         CP_UTF8,
         WC_ERR_INVALID_CHARS,
         wideCharString.data(),
         static_cast<int>(wideCharString.size()),
         utf8String.data(),
         static_cast<int>(utf8String.size()),
         nullptr,
         nullptr
      ),
   };
   if (0 >= utf8StringSize) [[unlikely]]
   {
      utf8String.resize(0);
      return std::error_code{static_cast<int>(GetLastError()), std::system_category(),};
   }
   assert(static_cast<size_t>(utf8StringSize) <= utf8String.size());
   utf8String.resize(static_cast<size_t>(utf8StringSize));
   return std::error_code{};
}

}
