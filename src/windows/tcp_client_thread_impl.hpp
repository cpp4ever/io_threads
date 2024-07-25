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

#include "tcp_client_thread_worker.hpp" ///< for io_threads::tcp_client_thread::tcp_client::tcp_client_thread_worker
#include "winapi_error.hpp" ///< for io_threads::check_winapi_error

#include "io_threads/tcp_client.hpp" ///< for io_threads::tcp_client_thread::tcp_client
#include "io_threads/tcp_client_thread.hpp" ///< for io_threads::tcp_client_thread

/// for
///   DWORD_PTR,
///   GetCurrentThread,
///   SetThreadAffinityMask
#include <Windows.h>

#include <cassert> ///< for assert
#include <cstddef> ///< for size_t
#include <cstdint> ///< for uint16_t
#include <future> ///< for std::future, std::promise
#include <memory> ///< for std::addressof
#include <stop_token> ///< for std::stop_token
#include <thread> ///< for std::jthread

#pragma comment(lib, "kernel32.lib")

namespace io_threads
{

class tcp_client_thread::tcp_client_thread_impl final
{
private:
   class winsock_scope final
   {
   public:
      [[nodiscard]] winsock_scope()
      {
         auto wsaVersion = MAKEWORD(2, 2);
         WSADATA wsaData = {};
         if (
            auto const returnCode = WSAStartup(wsaVersion, std::addressof(wsaData));
            ERROR_SUCCESS != returnCode
         )
         {
            log_system_error(
               std::source_location::current(),
               "[tcp_client] failed to initialize WinSock 2.2: ({}) - {}",
               returnCode
            );
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
         if (auto const returnCode = WSACleanup(); ERROR_SUCCESS != returnCode)
         {
            log_system_error(
               std::source_location::current(),
               "[tcp_client] failed to terminate use of WinSock 2.2: ({}) - {}",
               returnCode
            );
         }
      }

      winsock_scope &operator = (winsock_scope &&) = delete;
      winsock_scope &operator = (winsock_scope const &) = delete;
   };

public:
   tcp_client_thread_impl() = delete;
   tcp_client_thread_impl(tcp_client_thread_impl &&) = delete;
   tcp_client_thread_impl(tcp_client_thread_impl const &) = delete;

   tcp_client_thread_impl(
      uint16_t const cpuId,
      size_t const initialCapacityOfSocketDescriptorList,
      size_t const recvBufferSize,
      size_t const sendBufferSize
   )
   {
      std::promise<tcp_client::tcp_client_thread_worker &> workerPromise{};
      auto workerFuture = workerPromise.get_future();
      m_thread = std::jthread
      {
         [cpuId, initialCapacityOfSocketDescriptorList, recvBufferSize, sendBufferSize, &workerPromise] (std::stop_token const stopToken)
         {
            if (0 == SetThreadAffinityMask(GetCurrentThread(), static_cast<DWORD_PTR>(1) << cpuId)) [[unlikely]]
            {
               check_winapi_error("[tcp_client] failed to pin thread to cpu core: ({}) - {}");
            }
            [[maybe_unused]] static winsock_scope const winsockScope{};
            tcp_client::tcp_client_thread_worker worker{initialCapacityOfSocketDescriptorList, recvBufferSize, sendBufferSize};
            workerPromise.set_value(worker);
            worker.start(stopToken);
         }
      };
      m_worker = std::addressof(workerFuture.get());
   }

   ~tcp_client_thread_impl()
   {
      assert(nullptr != m_worker);
      assert(false == m_thread.get_stop_token().stop_requested());
      m_thread.request_stop();
      m_worker->stop();
      m_worker = nullptr;
      m_thread.join();
   }

   tcp_client_thread_impl &operator = (tcp_client_thread_impl &&) = delete;
   tcp_client_thread_impl &operator = (tcp_client_thread_impl const &) = delete;

   void ready_to_connect(tcp_client_thread::tcp_client &client) const
   {
      assert(nullptr != m_worker);
      m_worker->ready_to_connect(client);
   }

   void ready_to_disconnect(tcp_client_thread::tcp_client &client) const
   {
      assert(nullptr != m_worker);
      m_worker->ready_to_disconnect(client);
   }

   void ready_to_send(tcp_client_thread::tcp_client &client) const
   {
      assert(nullptr != m_worker);
      m_worker->ready_to_send(client);
   }

private:
   tcp_client::tcp_client_thread_worker *m_worker = nullptr;
   std::jthread m_thread = {};
};

}
