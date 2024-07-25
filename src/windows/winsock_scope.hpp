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

#include "common/logger.hpp" ///< for io_threads::log_error, io_threads::log_system_error
#include "common/utility.hpp" ///< for io_threads::unreachable

/// for
///   ERROR_SUCCESS,
///   HIBYTE,
///   LOBYTE,
///   MAKEWORD,
///   WSADATA,
///   WSACleanup,
///   WSAStartup
#include <WinSock2.h>

#include <memory> ///< for std::addressof
#include <source_location> ///< for std::source_location

#pragma comment(lib, "WS2_32")

namespace io_threads
{

class winsock_scope final
{
public:
   [[nodiscard]] winsock_scope()
   {
      auto wsaVersion{MAKEWORD(2, 2),};
      WSADATA wsaData{};
      if (
         auto const returnCode{WSAStartup(wsaVersion, std::addressof(wsaData)),};
         ERROR_SUCCESS != returnCode
      )
      {
         log_system_error("[tcp_client] failed to initialize WinSock 2.2: ({}) - {}", returnCode);
         unreachable();
      }
      if ((2 != LOBYTE(wsaData.wVersion)) || (2 != HIBYTE(wsaData.wVersion)))
      {
         log_error(
            std::source_location::current(),
            "[tcp_client] failed to initialize WinSock 2.2: current version is {}.{}",
            HIBYTE(wsaData.wVersion),
            LOBYTE(wsaData.wVersion)
         );
         unreachable();
      }
   }

   winsock_scope(winsock_scope &&) = delete;
   winsock_scope(winsock_scope const &) = delete;

   ~winsock_scope()
   {
      if (auto const returnCode{WSACleanup(),}; ERROR_SUCCESS != returnCode)
      {
         log_system_error("[tcp_client] failed to terminate use of WinSock 2.2: ({}) - {}", returnCode);
      }
   }

   winsock_scope &operator = (winsock_scope &&) = delete;
   winsock_scope &operator = (winsock_scope const &) = delete;
};

}
