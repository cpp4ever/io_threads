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

#include "completion_port.hpp" ///< for io_threads::completion_port, io_threads::to_completion_key
#include "tcp_client_command.hpp" ///< for io_threads::tcp_client_command, io_threads::to_completion_overlapped
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
      std::promise<completion_port const &> completionPortPromise{};
      auto completionPortFuture = completionPortPromise.get_future();
      m_thread = std::jthread
      {
         [cpuId, initialCapacityOfSocketDescriptorList, recvBufferSize, sendBufferSize, &completionPortPromise] (std::stop_token const stopToken)
         {
            if (0 == SetThreadAffinityMask(GetCurrentThread(), static_cast<DWORD_PTR>(1) << cpuId)) [[unlikely]]
            {
               check_winapi_error("[io_threads] failed to pin thread to cpu core: ({}) - {}");
            }
            tcp_client::tcp_client_thread_worker worker{initialCapacityOfSocketDescriptorList, recvBufferSize, sendBufferSize, completionPortPromise};
            worker.run(stopToken);
         }
      };
      m_completionPort = std::addressof(completionPortFuture.get());
   }

   ~tcp_client_thread_impl()
   {
      assert(nullptr != m_completionPort);
      assert(false == m_thread.get_stop_token().stop_requested());
      m_thread.request_stop();
      m_completionPort->post_queued_completion_status(0, to_completion_overlapped(tcp_client_command::unknown));
      m_completionPort = nullptr;
      m_thread.join();
   }

   tcp_client_thread_impl &operator = (tcp_client_thread_impl &&) = delete;
   tcp_client_thread_impl &operator = (tcp_client_thread_impl const &) = delete;

   void ready_to_connect(tcp_client_thread::tcp_client &client) const
   {
      assert(nullptr != m_completionPort);
      m_completionPort->post_queued_completion_status(
         to_completion_key(client),
         to_completion_overlapped(tcp_client_command::ready_to_connect)
      );
   }

   void ready_to_disconnect(tcp_client_thread::tcp_client &client) const
   {
      assert(nullptr != m_completionPort);
      m_completionPort->post_queued_completion_status(
         to_completion_key(client),
         to_completion_overlapped(tcp_client_command::ready_to_disconnect)
      );
   }

   void ready_to_send(tcp_client_thread::tcp_client &client) const
   {
      assert(nullptr != m_completionPort);
      m_completionPort->post_queued_completion_status(
         to_completion_key(client),
         to_completion_overlapped(tcp_client_command::ready_to_send)
      );
   }

private:
   completion_port const *m_completionPort = nullptr;
   std::jthread m_thread = {};
};

}
