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
#include "common/tcp_client_command.hpp" ///< for io_threads::tcp_client_command
#include "common/thread_task.hpp" ///< for io_threads::thread_task
#include "common/utility.hpp" ///< for io_threads::to_underlying, io_threads::unreachable
#include "io_threads/data_chunk.hpp" ///< for io_threads::data_chunk
#include "io_threads/network_interface.hpp" ///< for io_threads::network_interface
#include "io_threads/tcp_client.hpp" ///< for io_threads::tcp_client
#include "io_threads/tcp_client_config.hpp" ///< for io_threads::tcp_client_config
#include "io_threads/tcp_keep_alive.hpp" ///< for io_threads::tcp_keep_alive
#include "linux/socket_address_impl.hpp" ///< for io_threads::socket_address::socket_address_impl
#include "linux/tcp_socket_descriptor.hpp" ///< for io_threads::tcp_socket_descriptor
#include "linux/tcp_socket_operation.hpp" ///< for io_threads::tcp_socket_operation
#include "linux/tcp_socket_options.hpp" ///< for io_threads::tcp_socket_options
#include "linux/thread_affinity.hpp" ///< for io_threads::set_thread_affinity
#include "linux/uring_command_queue.hpp" ///< for io_threads::uring_command_queue
#include "linux/uring_listener.hpp" ///< for io_threads::uring_listener
#include "linux/uring_stop_token.hpp" ///< for io_threads::uring_stop_token
#include "linux/uring_worker.hpp" ///< for io_threads::uring_worker

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

class tcp_client::tcp_client_thread_worker final : public uring_listener
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
         m_uringCommandQueue.push(static_cast<intptr_t>(tcp_client_command::execute), std::bit_cast<intptr_t>(std::addressof(ioTask)));
         ioTask.completionFuture.wait();
      }
   }

   void ready_to_connect(tcp_client &tcpClient)
   {
      if (std::this_thread::get_id() == m_threadId)
      {
         handle_ready_to_connect(tcpClient);
      }
      else
      {
         m_uringCommandQueue.push(static_cast<intptr_t>(tcp_client_command::ready_to_connect), std::bit_cast<intptr_t>(std::addressof(tcpClient)));
      }
   }

   void ready_to_disconnect(tcp_client &tcpClient)
   {
      if (std::this_thread::get_id() == m_threadId)
      {
         handle_ready_to_disconnect(tcpClient);
      }
      else
      {
         m_uringCommandQueue.push(static_cast<intptr_t>(tcp_client_command::ready_to_disconnect), std::bit_cast<intptr_t>(std::addressof(tcpClient)));
      }
   }

   void ready_to_send(tcp_client &tcpClient)
   {
      if (std::this_thread::get_id() == m_threadId)
      {
         handle_ready_to_send(tcpClient);
      }
      else
      {
         m_uringCommandQueue.push(static_cast<intptr_t>(tcp_client_command::ready_to_send), std::bit_cast<intptr_t>(std::addressof(tcpClient)));
      }
   }

   void stop()
   {
      m_uringCommandQueue.push(static_cast<intptr_t>(tcp_client_command::unknown), 0);
   }

   [[nodiscard]] static std::jthread start(
      uint16_t const coreCpuId,
      size_t const capacityOfSocketDescriptorList,
      size_t const capacityOfInputOutputBuffer,
      std::promise<tcp_client_thread_worker &> &workerPromise
   )
   {
      return std::jthread
      {
         [coreCpuId, capacityOfSocketDescriptorList, capacityOfInputOutputBuffer, &workerPromise] (std::stop_token const stopToken)
         {
            if (auto const returnCode{set_thread_affinity(coreCpuId),}; 0 != returnCode)
            {
               log_system_error(std::source_location::current(), "[tcp_thread] failed to pin thread to cpu core: ({}) - {}", returnCode);
               unreachable();
            }
            tcp_client_thread_worker threadWorker{stopToken, capacityOfSocketDescriptorList, capacityOfInputOutputBuffer,};
            assert(nullptr != threadWorker.m_uringWorker);
            workerPromise.set_value(threadWorker);
            while (
               false
               || (false == threadWorker.m_uringStopToken.stop_possible())
               || (false == threadWorker.m_uringStopToken.stop_requested())
            )
            {
               threadWorker.m_uringWorker->submit_and_wait(threadWorker);
            }
         }
      };
   }

private:
   std::unique_ptr<uring_worker> const m_uringWorker;
   uring_stop_token m_uringStopToken;
   std::jthread::id const m_threadId{std::this_thread::get_id(),};
   uring_command_queue m_uringCommandQueue;
   tcp_socket_operation *m_tcpSocketOperations{nullptr,};
   tcp_socket_descriptor *m_tcpSocketDescriptors{nullptr,};

   [[nodiscard]] tcp_client_thread_worker(
      std::stop_token const &stopToken,
      size_t const capacityOfSocketDescriptorList,
      size_t const capacityOfInputOutputBuffer
   ) :
      m_uringWorker{std::make_unique<uring_worker>(capacityOfSocketDescriptorList * 2 + 1),},
      m_uringStopToken{stopToken,},
      m_uringCommandQueue{capacityOfSocketDescriptorList,}
   {
      assert(0 < capacityOfInputOutputBuffer);
      m_tcpSocketOperations = m_uringWorker->register_tcp_socket_operations(
         capacityOfSocketDescriptorList * 2,
         tcp_socket_operation::total_size(std::max(sizeof(tcp_socket_options), capacityOfInputOutputBuffer))
      );
      m_tcpSocketDescriptors = m_uringWorker->register_tcp_socket_descriptors(capacityOfSocketDescriptorList);
      m_uringCommandQueue.prep_read(m_uringWorker->submission_entry(this));
      m_uringStopToken.increment_tasks_count();
   }

   ~tcp_client_thread_worker()
   {
      m_uringWorker->unregister_tcp_socket_descriptors(m_tcpSocketDescriptors);
      m_uringWorker->unregister_tcp_socket_operations(m_tcpSocketOperations);
   }

   void connect(tcp_client &tcpClient)
   {
      assert(nullptr != tcpClient.m_socketDescriptor);
      assert(tcp_socket_status::connecting == tcpClient.m_socketDescriptor->tcpSocketStatus);
      assert(std::addressof(tcpClient) == tcpClient.m_socketDescriptor->tcpClient);
      /*auto &tcpSocketDescriptor = *tcpClient.m_socketDescriptor;
      auto &submissionQueueEntry = m_uringWorker->submission_entry(std::addressof(tcpSocketDescriptor));
      io_uring_prep_connect(
         std::addressof(submissionQueueEntry),
         tcpClient.m_socketDescriptor->registeredTcpSocketIndex,
      );*/
   }

   void disconnect(tcp_client &tcpClient)
   {
      (void)tcpClient;
   }

   void handle_command(intptr_t const commandId, intptr_t const commandTarget)
   {
      switch (commandId)
      {
      [[unlikely]] case to_underlying(tcp_client_command::unknown):
      {
         assert(0 == commandTarget);
         m_uringCommandQueue.prep_close(m_uringWorker->submission_entry(this));
         m_uringStopToken.increment_tasks_count();
      }
      break;

      case to_underlying(tcp_client_command::execute):
      {
         assert(0 != commandTarget);
         handle_thread_task(*std::bit_cast<thread_task *>(commandTarget));
      }
      break;

      case to_underlying(tcp_client_command::ready_to_connect):
      {
         assert(0 != commandTarget);
         handle_ready_to_connect(*std::bit_cast<tcp_client *>(commandTarget));
      }
      break;

      case to_underlying(tcp_client_command::ready_to_send):
      {
         assert(0 != commandTarget);
         handle_ready_to_send(*std::bit_cast<tcp_client *>(commandTarget));
      }
      break;

      case to_underlying(tcp_client_command::ready_to_disconnect):
      {
         assert(0 != commandTarget);
         handle_ready_to_disconnect(*std::bit_cast<tcp_client *>(commandTarget));
      }
      break;

      [[unlikely]] default:
      {
         log_error(std::source_location::current(), "[tcp_client] unknown tcp_client_command {}: it must be a bug", commandId);
         unreachable();
      }
      break;
      }
   }

   void handle_completion(intptr_t const userdata, int32_t const result, [[maybe_unused]] uint32_t const flags)
   {
      assert(0 != userdata);
      assert(0 == flags);
      if (std::bit_cast<intptr_t>(this) == userdata)
      {
         if (false == m_uringStopToken.stop_requested()) [[likely]]
         {
            m_uringCommandQueue.prep_read(m_uringWorker->submission_entry(this));
            m_uringStopToken.increment_tasks_count();
         }
         m_uringCommandQueue.handle_read(*this, result, flags);
         m_uringStopToken.decrement_tasks_count();
         return;
      }
/*
      auto &fileDescriptor{*std::bit_cast<file_descriptor *>(userdata),};
      assert(file_status::none != fileDescriptor.fileStatus);
      assert(nullptr == fileDescriptor.next);
      if (nullptr != fileDescriptor.fileWriter) [[likely]]
      {
         if (file_status::busy == fileDescriptor.fileStatus) [[likely]]
         {
            auto &fileWriter = *fileDescriptor.fileWriter;
            assert(std::addressof(fileDescriptor) == fileWriter.m_fileDescriptor);
            fileDescriptor.fileStatus = file_status::ready;
            if (0 <= result) [[likely]]
            {
               write(fileWriter);
            }
            else
            {
               close_file(fileWriter);
               std::error_code errorCode{-result, std::generic_category(),};
               fileWriter.io_closed(errorCode);
            }
         }
         else
         {
            assert(file_status::opening == fileDescriptor.fileStatus);
            fileDescriptor.fileStatus = file_status::ready;
            auto &fileWriter = *fileDescriptor.fileWriter;
            assert(std::addressof(fileDescriptor) == fileWriter.m_fileDescriptor);
            if (0 == result) [[likely]]
            {
               fileWriter.io_opened();
               write(fileWriter);
            }
            else
            {
               fileWriter.m_fileDescriptor = nullptr;
               fileDescriptor.fileStatus = file_status::none;
               fileDescriptor.closeOnCompletion = false;
               fileDescriptor.fileWriter = nullptr;
               fileDescriptor.next = m_freeFileDescriptors;
               m_freeFileDescriptors = std::addressof(fileDescriptor);
               std::error_code errorCode{-result, std::generic_category(),};
               fileWriter.io_closed(errorCode);
            }
         }
      }
      else if (file_status::flushing == fileDescriptor.fileStatus)
      {
         if (0 > result) [[unlikely]]
         {
            log_system_error(std::source_location::current(), "[file_writer] failed to flush file buffers: ({}) - {}", -result);
         }
         auto &submissionQueueEntry{m_uringWorker->submission_entry(std::addressof(fileDescriptor)),};
         fileDescriptor.fileStatus = file_status::closing;
         io_uring_prep_close_direct(std::addressof(submissionQueueEntry), fileDescriptor.registeredFileIndex);
         m_uringStopToken.increment_tasks_count();
      }
      else if (file_status::closing == fileDescriptor.fileStatus)
      {
         if (0 > result) [[unlikely]]
         {
            log_system_error(std::source_location::current(), "[file_writer] failed to close file: ({}) - {}", -result);
         }
         fileDescriptor.fileStatus = file_status::none;
         fileDescriptor.closeOnCompletion = false;
         fileDescriptor.next = m_freeFileDescriptors;
         m_freeFileDescriptors = std::addressof(fileDescriptor);
      }
      else
      {
         log_error(std::source_location::current(), "[file_writer] unexpected file status {}: it must be a bug", to_underlying(fileDescriptor.fileStatus));
         unreachable();
      }
*/
      m_uringStopToken.decrement_tasks_count();
   }

   void handle_connect_completion(tcp_client &tcpClient)
   {
      (void)tcpClient;
   }

   void handle_disconnect_completion(tcp_client &tcpClient)
   {
      handle_disconnected(tcpClient, std::error_code{});
   }

   void handle_disconnected(tcp_client &tcpClient, std::error_code errorCode)
   {
      assert(nullptr != tcpClient.m_socketDescriptor);
      //auto *socketDescriptor{std::launder(tcpClient.m_socketDescriptor)};
      //m_socketMemory->push_object(*socketDescriptor);
      tcpClient.io_disconnected(errorCode);
   }

   void handle_ready_to_connect(tcp_client &tcpClient)
   {
      assert(nullptr == tcpClient.m_socketDescriptor);
      if (nullptr == m_tcpSocketDescriptors) [[unlikely]]
      {
         log_error(std::source_location::current(), "[tcp_client] too few socket descriptors provided, please increase capacity of socket descriptor list");
         unreachable();
      }
      auto &tcpSocketDescriptor{*std::launder(m_tcpSocketDescriptors)};
      m_tcpSocketDescriptors = std::launder(tcpSocketDescriptor.next);
      tcpSocketDescriptor.next = nullptr;
      assert(tcp_socket_status::none == tcpSocketDescriptor.tcpSocketStatus);
      assert(false == tcpSocketDescriptor.disconnectOnCompletion);
      assert(nullptr == tcpSocketDescriptor.tcpClient);
      assert(false == (bool{tcpSocketDescriptor.disconnectReason,}));
      tcpClient.m_socketDescriptor = std::addressof(tcpSocketDescriptor);
      tcpSocketDescriptor.tcpSocketStatus = tcp_socket_status::connecting;
      tcpSocketDescriptor.tcpClient = std::addressof(tcpClient);
      auto &config = *std::launder(std::construct_at(
         std::bit_cast<tcp_client_config *>(std::addressof(tcpSocketDescriptor)),
         tcpClient.io_ready_to_connect()
      ));
      io_uring_prep_socket_direct(
         std::addressof(m_uringWorker->submission_entry(tcpClient.m_socketDescriptor)),
         config.peer_address().socket_address()->sockaddr().addressFamily,
         SOCK_STREAM | SOCK_NONBLOCK,
         IPPROTO_TCP,
         tcpClient.m_socketDescriptor->registeredTcpSocketIndex,
         0
      );
      m_uringStopToken.increment_tasks_count();
   }

   void handle_ready_to_disconnect(tcp_client &tcpClient)
   {
      assert(nullptr != tcpClient.m_socketDescriptor);
      auto &socketDescriptor{*tcpClient.m_socketDescriptor};
      (void)socketDescriptor;
   }

   void handle_ready_to_send(tcp_client &tcpClient)
   {
      assert(nullptr != tcpClient.m_socketDescriptor);
      (void)tcpClient;
   }

   void handle_recv_completion(tcp_client &tcpClient)
   {
      assert(nullptr != tcpClient.m_socketDescriptor);
      auto &socketDescriptor{*tcpClient.m_socketDescriptor};
      (void)socketDescriptor;
   }

   void handle_received_data(tcp_client &tcpClient, size_t const bytesReceived)
   {
      assert(nullptr != tcpClient.m_socketDescriptor);
      auto &socketDescriptor{*tcpClient.m_socketDescriptor};
      (void)socketDescriptor;
      (void)bytesReceived;
   }

   void handle_send_completion(tcp_client &tcpClient)
   {
      assert(nullptr != tcpClient.m_socketDescriptor);
      auto &socketDescriptor{*tcpClient.m_socketDescriptor};
      (void)socketDescriptor;
   }

   void handle_thread_task(thread_task &task)
   {
      assert(task.routine);
      task.routine();
      task.completionPromise.set_value();
   }

   void recv(tcp_client &tcpClient)
   {
      assert(nullptr != tcpClient.m_socketDescriptor);
      auto &socketDescriptor{*tcpClient.m_socketDescriptor};
      (void)socketDescriptor;
   }

   void send(tcp_client &tcpClient)
   {
      assert(nullptr != tcpClient.m_socketDescriptor);
      auto &socketDescriptor{*tcpClient.m_socketDescriptor};
      (void)socketDescriptor;
   }
};

}
