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

#include "common/logger.hpp" ///< for io_threads::log_error
#include "common/memory_pool.hpp" ///< for io_threads::memory_pool
#include "common/thread_task.hpp" ///< for io_threads::thread_task
#include "common/utility.hpp" ///< for io_threads::to_underlying, io_threads::unreachable
#include "io_threads/data_chunk.hpp" ///< for io_threads::data_chunk
#include "io_threads/network_interface.hpp" ///< for io_threads::network_interface
#include "io_threads/tcp_client.hpp" ///< for io_threads::tcp_client
#include "io_threads/tcp_client_config.hpp" ///< for io_threads::tcp_client_config
#include "io_threads/tcp_keep_alive.hpp" ///< for io_threads::tcp_keep_alive
#include "linux/socket_address_impl.hpp" ///< for io_threads::socket_address::socket_address_impl
#include "linux/tcp_socket_descriptor.hpp" ///< for io_threads::tcp_socket_descriptor

#include <algorithm> ///< for std::max
#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <chrono> ///< for std::chrono::milliseconds
#include <cstddef> ///< for size_t, std::byte
#include <cstdint> ///< for uint16_t
#include <functional> ///< for std::function
#include <future> ///< for std::promise
#include <memory> ///< for std::addressof, std::make_unique, std::unique_ptr
#include <new> ///< for std::align_val_t
#include <source_location> ///< for std::source_location
#include <stop_token> ///< for std::stop_token
#include <system_error> ///< for std::error_code, std::system_category
#include <thread> ///< for std::jthread, std::this_thread

namespace io_threads
{

class tcp_client::tcp_client_thread_worker final
{
public:
   tcp_client_thread_worker() = delete;
   tcp_client_thread_worker(tcp_client_thread_worker &&) = delete;
   tcp_client_thread_worker(tcp_client_thread_worker const &) = delete;

   tcp_client_thread_worker &operator = (tcp_client_thread_worker &&) = delete;
   tcp_client_thread_worker &operator = (tcp_client_thread_worker const &) = delete;

   void execute(std::function<void()> const &ioRoutine)
   {
      assert(true == bool{ioRoutine});
      if (std::this_thread::get_id() == m_threadId)
      {
         ioRoutine();
      }
      else
      {
         thread_task const ioTask
         {
            .routine{ioRoutine},
         };
         // m_completionPort.post_queued_completion_status(
         //    to_completion_key(ioTask),
         //    to_completion_overlapped(tcp_client_command::execute)
         // );
         ioTask.completionFuture.wait();
      }
   }

   void ready_to_connect(tcp_client &client)
   {
      if (std::this_thread::get_id() == m_threadId)
      {
         handle_ready_to_connect(client);
      }
      else
      {
         // m_completionPort.post_queued_completion_status(
         //    to_completion_key(client),
         //    to_completion_overlapped(tcp_client_command::ready_to_connect)
         // );
      }
   }

   void ready_to_disconnect(tcp_client &client)
   {
      if (std::this_thread::get_id() == m_threadId)
      {
         handle_ready_to_disconnect(client);
      }
      else
      {
         // m_completionPort.post_queued_completion_status(
         //    to_completion_key(client),
         //    to_completion_overlapped(tcp_client_command::ready_to_disconnect)
         // );
      }
   }

   void ready_to_send(tcp_client &client)
   {
      if (std::this_thread::get_id() == m_threadId)
      {
         handle_ready_to_send(client);
      }
      else
      {
         // m_completionPort.post_queued_completion_status(
         //    to_completion_key(client),
         //    to_completion_overlapped(tcp_client_command::ready_to_send)
         // );
      }
   }

   void stop()
   {
      // m_completionPort.post_queued_completion_status(0, to_completion_overlapped(tcp_client_command::unknown));
   }

   [[nodiscard]] static std::jthread start(
      uint16_t const coreCpuId,
      size_t const initialCapacityOfSocketDescriptorList,
      size_t const capacityOfInputOutputBuffers,
      std::promise<tcp_client_thread_worker &> &workerPromise
   )
   {
      return std::jthread
      {
         [coreCpuId, initialCapacityOfSocketDescriptorList, capacityOfInputOutputBuffers, &workerPromise] (std::stop_token const stopToken)
         {
            (void)coreCpuId;
            // if (0 == SetThreadAffinityMask(GetCurrentThread(), static_cast<DWORD_PTR>(1) << coreCpuId)) [[unlikely]]
            // {
            //    check_winapi_error("[tcp_client] failed to pin thread to cpu core: ({}) - {}");
            // }
            tcp_client_thread_worker worker{initialCapacityOfSocketDescriptorList, capacityOfInputOutputBuffers};
            workerPromise.set_value(worker);
            while (false == stopToken.stop_requested()) [[likely]]
            {
               // auto timeoutMilliseconds{completion_port::infinite_timeout};
               // while (m_completionPortEntries->size() == poll(timeoutMilliseconds))
               // {
               //    /// Do while there are entries to poll
               //    timeoutMilliseconds = completion_port::no_timeout;
               // }
            }
            // while (0 != poll(completion_port::no_timeout))
            // {
            //    /// Until all entries are polled
            // }
         }
      };
   }

private:
   std::jthread::id const m_threadId{std::this_thread::get_id()};
   // std::unique_ptr<memory_pool> const m_ioMemory;
   std::unique_ptr<memory_pool> const m_socketMemory;

   [[nodiscard]] tcp_client_thread_worker(
      size_t const initialCapacityOfSocketDescriptors,
      size_t const capacityOfInputOutputBuffers
   ) :
      // m_ioMemory
      // {
      //    std::make_unique<memory_pool>(
      //       initialCapacityOfSocketDescriptors * 2,
      //       std::align_val_t{std::max(alignof(tcp_connectivity_context), alignof(tcp_data_transfer_context))},
      //       std::max(
      //          sizeof(tcp_connectivity_context) + std::max(sizeof(SOCKADDR_IN), sizeof(SOCKADDR_IN6)),
      //          sizeof(tcp_data_transfer_context) + capacityOfInputOutputBuffers
      //       )
      //    )
      // },
      m_socketMemory
      {
         std::make_unique<memory_pool>(
            initialCapacityOfSocketDescriptors,
            std::align_val_t{alignof(tcp_socket_descriptor)},
            sizeof(tcp_socket_descriptor)
         )
      }
   {
      assert(0 < capacityOfInputOutputBuffers);
   }

   void connect(tcp_client &client)
   {
      (void)client;
   }

   void disconnect(tcp_client &client)
   {
      (void)client;
   }

   void handle_connect_completion(tcp_client &client)
   {
      (void)client;
   }

   void handle_disconnect_completion(tcp_client &client)
   {
      handle_disconnected(client, std::error_code{});
   }

   void handle_disconnected(tcp_client &client, std::error_code errorCode)
   {
      assert(nullptr != client.m_socketDescriptor);
      auto *socketDescriptor{std::launder(client.m_socketDescriptor)};
      m_socketMemory->push_object(*socketDescriptor);
      client.io_disconnected(errorCode);
   }

   void handle_ready_to_connect(tcp_client &client)
   {
      assert(nullptr == client.m_socketDescriptor);
      auto const config{client.io_ready_to_connect()};
      auto const &socketAddress{config.peer_address().socket_address()->sockaddr()};
      (void)socketAddress;
   }

   void handle_ready_to_disconnect(tcp_client &client)
   {
      assert(nullptr != client.m_socketDescriptor);
      auto &socketDescriptor{*client.m_socketDescriptor};
      (void)socketDescriptor;
   }

   void handle_ready_to_send(tcp_client &client)
   {
      assert(nullptr != client.m_socketDescriptor);
   }

   void handle_recv_completion(tcp_client &client)
   {
      assert(nullptr != client.m_socketDescriptor);
      auto &socketDescriptor{*client.m_socketDescriptor};
      (void)socketDescriptor;
   }

   void handle_received_data(tcp_client &client, size_t const bytesReceived)
   {
      assert(nullptr != client.m_socketDescriptor);
      auto &socketDescriptor{*client.m_socketDescriptor};
      (void)socketDescriptor;
      (void)bytesReceived;
   }

   void handle_send_completion(tcp_client &client)
   {
      assert(nullptr != client.m_socketDescriptor);
      auto &socketDescriptor{*client.m_socketDescriptor};
      (void)socketDescriptor;
   }

   void handle_thread_task(thread_task &task)
   {
      assert(task.routine);
      task.routine();
      task.completionPromise.set_value();
   }

   void recv(tcp_client &client)
   {
      assert(nullptr != client.m_socketDescriptor);
      auto &socketDescriptor{*client.m_socketDescriptor};
      (void)socketDescriptor;
   }

   void send(tcp_client &client)
   {
      assert(nullptr != client.m_socketDescriptor);
      auto &socketDescriptor{*client.m_socketDescriptor};
      (void)socketDescriptor;
   }
};

}
