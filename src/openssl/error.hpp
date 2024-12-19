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

#include <openssl/err.h> ///< for ERR_get_error_all, ERR_GET_LIB, ERR_TXT_STRING

#include <cassert> ///< for assert
#include <cstdint> ///< for uint32_t
#include <iostream> ///< for std::cerr
#include <memory> ///< for std::addressof
#include <ostream> ///< for std::endl
#include <source_location> ///< for std::source_location
#include <syncstream> ///< for std::osyncstream
#include <sstream> ///< for std::stringstream
#include <string_view> ///< for std::string_view

namespace io_threads
{

inline void log_openssl_errors(std::string_view const &prefix, std::source_location const &sourceLocation = std::source_location::current())
{
   std::stringstream sink{};
   unsigned long errorCode{0,};
   char const *errorLocationFilePath{"",};
   int errorLocationFileLine{0,};
   char const *errorLocationFunctionName{"",};
   char const *errorData{"",};
   int errorFlags{0,};
   while (
      (
         errorCode = ERR_get_error_all(
            std::addressof(errorLocationFilePath),
            std::addressof(errorLocationFileLine),
            std::addressof(errorLocationFunctionName),
            std::addressof(errorData),
            std::addressof(errorFlags)
         )
      ) != 0
   )
   {
      sink << std::endl << "\t[openssl:";
      auto const libraryId{ERR_GET_LIB(errorCode),};
      auto const *libraryName{ERR_lib_error_string(libraryId),};
      if (nullptr == libraryName)
      {
         sink << "lib(" << static_cast<uint32_t>(libraryId) << ")";
      }
      else
      {
         sink << libraryName;
      }
      sink << "@" << errorLocationFilePath << ":" << errorLocationFunctionName << ":" << errorLocationFileLine << "] ";
      auto const errorReasonId{ERR_GET_REASON(errorCode),};
      auto const *errorReason{ERR_reason_error_string(errorReasonId),};
      if (nullptr == errorReason)
      {
         sink << "reason(" << static_cast<uint32_t>(errorReasonId) << ")";
      }
      else
      {
         sink << errorReason;
      }
      if (ERR_TXT_STRING != (ERR_TXT_STRING & errorFlags))
      {
         errorData = "";
      }
      sink << ": (" << std::hex << errorCode << std::dec << ") - " << errorData;
   }
   std::osyncstream{std::cerr,}
      << sourceLocation.file_name() << ":" << sourceLocation.line()
      << " " << prefix << sink.str()
      << std::endl
   ;
}

}
