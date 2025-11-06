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
#include "common/memory_pool.hpp" ///< for io_threads::memory_pool
#include "common/tcp_client_command.hpp" ///< for io_threads::tcp_client_command
#include "common/tcp_deferred_task.hpp" ///< for io_threads::tcp_client::tcp_deferred_task
#include "common/thread_task.hpp" ///< for io_threads::thread_task
#include "common/utility.hpp" ///< for io_threads::to_underlying, io_threads::unreachable
#include "io_threads/data_chunk.hpp" ///< for io_threads::data_chunk
#include "io_threads/network_interface.hpp" ///< for io_threads::network_interface
#include "io_threads/tcp_client.hpp" ///< for io_threads::tcp_client
#include "io_threads/thread_config.hpp" ///< for io_threads::shared_cpu_affinity_config, io_threads::thread_config
#include "io_threads/time.hpp" ///< for io_threads::system_clock, io_threads::system_time
#include "linux/tcp_client_uring.hpp" ///< for io_threads::tcp_client_uring
#include "linux/tcp_socket_descriptor.hpp" ///< for io_threads::tcp_socket_descriptor, io_threads::tcp_socket_status
#include "linux/tcp_socket_operation.hpp" ///< for io_threads::tcp_socket_operation, io_threads::tcp_socket_operation_type, io_threads::log_socket_error
#include "linux/tcp_socket_options.hpp" ///< for io_threads::tcp_socket_options
#include "linux/thread_affinity.hpp" ///< for io_threads::set_thread_affinity
#include "linux/uring_command_queue.hpp" ///< for io_threads::uring_command_queue
#include "linux/uring_listener.hpp" ///< for io_threads::uring_listener

#include <liburing.h> ///< for IORING_CQE_F_MORE, IORING_CQE_F_NOTIF, IO_URING_VERSION_MAJOR, IO_URING_VERSION_MINOR
#include <linux/time_types.h> ///< for __kernel_timespec
#include <netinet/ip.h> ///< for IP_TOS, IPPROTO_IP
#include <netinet/tcp.h> ///< for IPPROTO_TCP, TCP_NODELAY, TCP_KEEPCNT, TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_SYNCNT, TCP_USER_TIMEOUT
#include <sys/socket.h> ///< for setsockopt, SHUT_RDWR, SO_BINDTODEVICE, SO_KEEPALIVE, SOL_SOCKET
#include <unistd.h> ///< for close

#include <algorithm> ///< for std::max
#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <cerrno> ///< for errno
#include <chrono> ///< for std::chrono::duration_cast, std::chrono::nanoseconds, std::chrono::seconds
#include <cstddef> ///< for size_t
#include <cstdint> ///< for int32_t, intptr_t, uint32_t
#include <cstring> ///< for std::memcpy, std::memmove, strnlen
#include <functional> ///< for std::function
#include <future> ///< for std::promise
#include <memory> ///< for std::addressof, std::construct_at, std::destroy_at, std::make_shared, std::make_unique, std::shared_ptr, std::unique_ptr
#include <new> ///< for std::align_val_t, std::launder
#include <source_location> ///< for std::source_location
#include <stop_token> ///< for std::stop_token
#include <system_error> ///< for std::error_code, std::generic_category
#include <thread> ///< for std::jthread, std::this_thread

namespace io_threads
{

class tcp_client::tcp_client_thread_worker final : public uring_listener
{
public:
   tcp_client_thread_worker() = delete;
   tcp_client_thread_worker(tcp_client_thread_worker &&) = delete;
   tcp_client_thread_worker(tcp_client_thread_worker const &) = delete;

   [[nodiscard]] tcp_client_thread_worker(
      std::unique_ptr<tcp_client_uring> tcpClientUring,
      size_t const socketListCapacity,
      size_t const ioBufferCapacity
   ) :
      m_tcpClientUring{std::move(tcpClientUring),},
      m_uringCommandQueue{socketListCapacity,},
      m_deferredTaskMemory{std::make_unique<shared_memory_pool>(socketListCapacity, std::align_val_t{alignof(tcp_deferred_task),}, sizeof(tcp_deferred_task)),}
   {
      m_tcpSocketOperations = m_tcpClientUring->register_tcp_socket_operations(
         socketListCapacity * 2,
         std::max(sizeof(tcp_socket_operation) + sizeof(tcp_socket_options), tcp_socket_operation::total_size(ioBufferCapacity))
      );
      assert(nullptr != m_tcpSocketOperations);
      m_tcpSocketDescriptors = m_tcpClientUring->register_tcp_socket_descriptors(socketListCapacity);
      assert(nullptr != m_tcpSocketDescriptors);
   }

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
         m_uringCommandQueue.push(to_underlying(tcp_client_command::execute), std::bit_cast<intptr_t>(std::addressof(ioTask)));
         m_tcpClientUring->wake();
         ioTask.completionFuture.wait();
      }
   }

   void ready_to_connect(tcp_client &tcpClient)
   {
      m_uringCommandQueue.push(to_underlying(tcp_client_command::ready_to_connect), std::bit_cast<intptr_t>(std::addressof(tcpClient)));
      m_tcpClientUring->wake();
   }

   void ready_to_connect_deferred(tcp_client &client, system_time const notBeforeTime)
   {
      auto &deferredTask
      {
         m_deferredTaskMemory->pop<tcp_deferred_task>(
            tcp_deferred_task{.client = client, .command = tcp_client_command::ready_to_connect, .notBeforeTime = notBeforeTime,}
         ),
      };
      if (std::this_thread::get_id() == m_threadId)
      {
         cancel_deferred_task(client);
         enqueue_deferred_task(deferredTask);
      }
      else
      {
         m_uringCommandQueue.push(to_underlying(tcp_client_command::deferred), std::bit_cast<intptr_t>(std::addressof(deferredTask)));
         m_tcpClientUring->wake();
      }
   }

   void ready_to_disconnect(tcp_client &tcpClient)
   {
      if ((std::this_thread::get_id() == m_threadId) && (nullptr == tcpClient.m_socketDescriptor))
      {
         return;
      }
      m_uringCommandQueue.push(to_underlying(tcp_client_command::ready_to_disconnect), std::bit_cast<intptr_t>(std::addressof(tcpClient)));
      m_tcpClientUring->wake();
   }

   void ready_to_send(tcp_client &tcpClient)
   {
      if (
         true
         && (std::this_thread::get_id() == m_threadId)
         && ((nullptr == tcpClient.m_socketDescriptor) || (tcp_socket_status::busy == tcpClient.m_socketDescriptor->tcpSocketStatus))
      )
      {
         return;
      }
      m_uringCommandQueue.push(to_underlying(tcp_client_command::ready_to_send), std::bit_cast<intptr_t>(std::addressof(tcpClient)));
      m_tcpClientUring->wake();
   }

   void ready_to_send_deferred(tcp_client &client, system_time const notBeforeTime)
   {
      if (std::this_thread::get_id() == m_threadId)
      {
         if ((nullptr == client.m_socketDescriptor) || (tcp_socket_status::busy == client.m_socketDescriptor->tcpSocketStatus))
         {
            return;
         }
         cancel_deferred_task(client);
         auto &deferredTask
         {
            m_deferredTaskMemory->pop<tcp_deferred_task>(
               tcp_deferred_task{.client = client, .command = tcp_client_command::ready_to_send, .notBeforeTime = notBeforeTime,}
            ),
         };
         enqueue_deferred_task(deferredTask);
      }
      else
      {
         auto const &deferredTask
         {
            m_deferredTaskMemory->pop<tcp_deferred_task>(
               tcp_deferred_task{.client = client, .command = tcp_client_command::ready_to_send, .notBeforeTime = notBeforeTime,}
            ),
         };
         m_uringCommandQueue.push(to_underlying(tcp_client_command::deferred), std::bit_cast<intptr_t>(std::addressof(deferredTask)));
         m_tcpClientUring->wake();
      }
   }

   [[nodiscard]] shared_cpu_affinity_config share_io_threads() const noexcept
   {
      return m_tcpClientUring->share_io_threads();
   }

   void stop()
   {
      m_uringCommandQueue.push(to_underlying(tcp_client_command::unknown), 0);
      m_tcpClientUring->wake();
   }

   [[nodiscard]] static std::jthread start(
      thread_config const &threadConfig,
      std::promise<std::shared_ptr<tcp_client_thread_worker>> &workerPromise
   )
   {
      return std::jthread
      {
         [threadConfig, &workerPromise] (std::stop_token const)
         {
            if (true == threadConfig.worker_cpu_affinity().has_value())
            {
               if (auto const returnCode{set_thread_affinity(threadConfig.worker_cpu_affinity().value()),}; 0 != returnCode)
               {
                  log_system_error("[tcp_thread] failed to pin thread to cpu core: ({}) - {}", returnCode);
                  unreachable();
               }
            }
            auto const threadWorker
            {
               std::make_shared<tcp_client_thread_worker>(
                  tcp_client_uring::construct(threadConfig.io_threads_affinity(), threadConfig.descriptor_list_capacity() * 2 + 1),
                  threadConfig.descriptor_list_capacity(),
                  threadConfig.io_buffer_capacity()
               ),
            };
            workerPromise.set_value(threadWorker);
            __kernel_timespec ioTimeout{};
            intptr_t tasksCount{0,};
            do
            {
               threadWorker->process_deferred_tasks();
               if (auto const *deferredTask{threadWorker->m_deferredTaskHead,}; nullptr != deferredTask)
               {
                  std::chrono::nanoseconds const timeoutNanoseconds
                  {
                     std::max<std::chrono::nanoseconds>(std::chrono::nanoseconds{0,}, deferredTask->notBeforeTime - system_clock::now())
                  };
                  auto const timeoutSeconds{std::chrono::duration_cast<std::chrono::seconds>(timeoutNanoseconds),};
                  ioTimeout.tv_sec = timeoutSeconds.count();
                  ioTimeout.tv_nsec = (timeoutNanoseconds - timeoutSeconds).count();
                  tasksCount = threadWorker->m_tcpClientUring->poll(*threadWorker, std::addressof(ioTimeout));
               }
               else
               {
                  tasksCount = threadWorker->m_tcpClientUring->poll(*threadWorker, nullptr);
               }
            } while (tasksCount > 0);
            threadWorker->m_tcpClientUring->unregister_tcp_socket_descriptors(threadWorker->m_tcpSocketDescriptors);
            threadWorker->m_tcpSocketDescriptors = nullptr;
            threadWorker->m_tcpClientUring->unregister_tcp_socket_operations(threadWorker->m_tcpSocketOperations);
            threadWorker->m_tcpSocketOperations = nullptr;
         }
      };
   }

private:
   std::jthread::id const m_threadId{std::this_thread::get_id(),};
   tcp_deferred_task *m_deferredTaskHead{nullptr,};
   tcp_deferred_task *m_deferredTaskTail{nullptr,};
   std::unique_ptr<tcp_client_uring> const m_tcpClientUring;
   uring_command_queue m_uringCommandQueue;
   tcp_socket_operation *m_tcpSocketOperations{nullptr,};
   tcp_socket_descriptor *m_tcpSocketDescriptors{nullptr,};
   std::unique_ptr<shared_memory_pool> const m_deferredTaskMemory;
   int const m_tcpSynCnt{1,};

   void cancel_deferred_task(tcp_client &tcpClient);
   void enqueue_deferred_task(tcp_deferred_task &deferredTask);

   void handle_command(intptr_t const commandId, intptr_t const commandTarget) override
   {
      assert(std::this_thread::get_id() == m_threadId);
      switch (commandId)
      {
      [[unlikely]] case to_underlying(tcp_client_command::unknown):
      {
         assert(0 == commandTarget);
         m_tcpClientUring->stop();
      }
      break;

      case to_underlying(tcp_client_command::deferred):
      {
         assert(0 != commandTarget);
         auto &deferredTask{*std::bit_cast<tcp_deferred_task *>(commandTarget),};
         auto &client{deferredTask.client,};
         assert(std::addressof(deferredTask) != client.m_deferredTask);
         cancel_deferred_task(client);
         if (system_clock::now() >= deferredTask.notBeforeTime)
         {
            handle_deferred_task(deferredTask);
         }
         else
         {
            enqueue_deferred_task(deferredTask);
         }
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
         auto &client{*std::bit_cast<tcp_client *>(commandTarget),};
         cancel_deferred_task(client);
         handle_ready_to_connect(client);
      }
      break;

      case to_underlying(tcp_client_command::ready_to_send):
      {
         assert(0 != commandTarget);
         auto &client{*std::bit_cast<tcp_client *>(commandTarget),};
         cancel_deferred_task(client);
         handle_ready_to_send(client);
      }
      break;

      case to_underlying(tcp_client_command::ready_to_disconnect):
      {
         assert(0 != commandTarget);
         auto &client{*std::bit_cast<tcp_client *>(commandTarget),};
         cancel_deferred_task(client);
         handle_ready_to_disconnect(client);
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

   void handle_connect_completion(tcp_socket_operation &tcpSocketOperation, int32_t result, [[maybe_unused]] uint32_t const flags)
   {
      assert(nullptr == tcpSocketOperation.next);
      assert(nullptr != tcpSocketOperation.descriptor);
      auto &tcpSocketDescriptor{*tcpSocketOperation.descriptor,};
      assert(0 < tcpSocketDescriptor.registeredSocketIndex);
      assert(tcp_socket_status::none != tcpSocketDescriptor.tcpSocketStatus);
      assert(tcp_socket_status::ready != tcpSocketDescriptor.tcpSocketStatus);
      assert(tcp_socket_status::busy != tcpSocketDescriptor.tcpSocketStatus);
      assert(tcp_socket_status::close != tcpSocketDescriptor.tcpSocketStatus);
      assert(1 == tcpSocketDescriptor.refsCount);
      assert(nullptr != tcpSocketDescriptor.tcpClient);
      assert(tcpSocketOperation.descriptor == tcpSocketDescriptor.tcpClient->m_socketDescriptor);
      assert(nullptr == tcpSocketDescriptor.next);
      assert(false == (bool{tcpSocketDescriptor.disconnectReason,}));
      assert(0 == tcpSocketOperation.bufferOffset);
      assert(tcp_socket_operation_type::none != tcpSocketOperation.type);
      assert(tcp_socket_operation_type::recv != tcpSocketOperation.type);
      assert(tcp_socket_operation_type::send != tcpSocketOperation.type);
      assert(tcp_socket_operation_type::disconnect != tcpSocketOperation.type);
      assert(tcp_socket_operation_type::shutdown != tcpSocketOperation.type);
      assert(tcp_socket_operation_type::close != tcpSocketOperation.type);
      assert(0 <= result);
      assert(0 == flags);
      if (tcp_socket_status::disconnect == tcpSocketDescriptor.tcpSocketStatus) [[unlikely]]
      {
         tcpSocketDescriptor.tcpSocketStatus = tcp_socket_status::close;
         std::destroy_at(std::bit_cast<tcp_socket_options *>(std::addressof(tcpSocketOperation) + 1));
#if ((2 < IO_URING_VERSION_MAJOR) || ((2 == IO_URING_VERSION_MAJOR) && (6 <= IO_URING_VERSION_MINOR)))
         prep_close(tcpSocketOperation);
#else
         if (tcp_socket_operation_type::socket == tcpSocketOperation.type)
         {
            close(result);
         }
         else
         {
            prep_close(tcpSocketOperation);
         }
#endif
         return;
      }
      auto &tcpSocketOptions = *std::bit_cast<tcp_socket_options *>(std::addressof(tcpSocketOperation) + 1);
      switch (tcpSocketOperation.type)
      {
      case tcp_socket_operation_type::socket:
      {
#if ((2 < IO_URING_VERSION_MAJOR) || ((2 == IO_URING_VERSION_MAJOR) && (6 <= IO_URING_VERSION_MINOR)))
         if (0 != tcpSocketOptions.soBindToDevice[0])
         {
            tcpSocketOperation.type = tcp_socket_operation_type::setopt_so_bindtodevice;
            m_tcpClientUring->prep_setsockopt(
               tcpSocketOperation,
               SOL_SOCKET,
               SO_BINDTODEVICE,
               tcpSocketOptions.soBindToDevice.data(),
               strnlen(tcpSocketOptions.soBindToDevice.data(), tcpSocketOptions.soBindToDevice.size())
            );
            break;
         }
      } [[fallthrough]];
      case tcp_socket_operation_type::setopt_so_bindtodevice:
      {
         assert(0 <= tcpSocketOptions.soKeepAlive);
         assert(1 >= tcpSocketOptions.soKeepAlive);
         if (0 != tcpSocketOptions.soKeepAlive)
         {
            tcpSocketOperation.type = tcp_socket_operation_type::setopt_so_keepalive;
            m_tcpClientUring->prep_setsockopt(tcpSocketOperation, SOL_SOCKET, SO_KEEPALIVE, tcpSocketOptions.soKeepAlive);
            break;
         }
      } [[fallthrough]];
      case tcp_socket_operation_type::setopt_so_keepalive:
      {
         if (0 != tcpSocketOptions.ipTos)
         {
            tcpSocketOperation.type = tcp_socket_operation_type::setopt_ip_tos;
            m_tcpClientUring->prep_setsockopt(tcpSocketOperation, IPPROTO_IP, IP_TOS, tcpSocketOptions.ipTos);
            break;
         }
      } [[fallthrough]];
      case tcp_socket_operation_type::setopt_ip_tos:
      {
         assert(0 <= tcpSocketOptions.tcpKeepCnt);
         if (0 < tcpSocketOptions.tcpKeepCnt)
         {
            tcpSocketOperation.type = tcp_socket_operation_type::setopt_tcp_keepcnt;
            m_tcpClientUring->prep_setsockopt(tcpSocketOperation, IPPROTO_TCP, TCP_KEEPCNT, tcpSocketOptions.tcpKeepCnt);
            break;
         }
      } [[fallthrough]];
      case tcp_socket_operation_type::setopt_tcp_keepcnt:
      {
         assert(0 <= tcpSocketOptions.tcpKeepIdle);
         if (0 < tcpSocketOptions.tcpKeepIdle)
         {
            tcpSocketOperation.type = tcp_socket_operation_type::setopt_tcp_keepidle;
            m_tcpClientUring->prep_setsockopt(tcpSocketOperation, IPPROTO_TCP, TCP_KEEPIDLE, tcpSocketOptions.tcpKeepIdle);
            break;
         }
      } [[fallthrough]];
      case tcp_socket_operation_type::setopt_tcp_keepidle:
      {
         assert(0 <= tcpSocketOptions.tcpKeepIntvl);
         if (0 < tcpSocketOptions.tcpKeepIntvl)
         {
            tcpSocketOperation.type = tcp_socket_operation_type::setopt_tcp_keepintvl;
            m_tcpClientUring->prep_setsockopt(tcpSocketOperation, IPPROTO_TCP, TCP_KEEPINTVL, tcpSocketOptions.tcpKeepIntvl);
            break;
         }
      } [[fallthrough]];
      case tcp_socket_operation_type::setopt_tcp_keepintvl:
      {
         assert(0 <= tcpSocketOptions.tcpNoDelay);
         assert(1 >= tcpSocketOptions.tcpNoDelay);
         if (1 == tcpSocketOptions.tcpNoDelay)
         {
            tcpSocketOperation.type = tcp_socket_operation_type::setopt_tcp_nodelay;
            m_tcpClientUring->prep_setsockopt(tcpSocketOperation, IPPROTO_TCP, TCP_NODELAY, tcpSocketOptions.tcpNoDelay);
            break;
         }
      } [[fallthrough]];
      case tcp_socket_operation_type::setopt_tcp_nodelay:
      {
         if (0 < tcpSocketOptions.tcpUserTimeout)
         {
            tcpSocketOperation.type = tcp_socket_operation_type::setopt_tcp_syncnt;
            m_tcpClientUring->prep_setsockopt(tcpSocketOperation, IPPROTO_TCP, TCP_SYNCNT, m_tcpSynCnt);
            break;
         }
      } [[fallthrough]];
      case tcp_socket_operation_type::setopt_tcp_syncnt:
      {
         assert(0 <= tcpSocketOptions.tcpUserTimeout);
         if (0 < tcpSocketOptions.tcpUserTimeout)
         {
            tcpSocketOperation.type = tcp_socket_operation_type::setopt_tcp_user_timeout;
            m_tcpClientUring->prep_setsockopt(tcpSocketOperation, IPPROTO_TCP, TCP_USER_TIMEOUT, tcpSocketOptions.tcpUserTimeout);
            break;
         }
      } [[fallthrough]];
      case tcp_socket_operation_type::setopt_tcp_user_timeout:
      {
         tcpSocketOperation.type = tcp_socket_operation_type::connect;
#else
         if (
            true
            && (0 != tcpSocketOptions.soBindToDevice[0])
            && (-1 == setsockopt(result, SOL_SOCKET, SO_BINDTODEVICE, tcpSocketOptions.soBindToDevice.data(), strnlen(tcpSocketOptions.soBindToDevice.data(), tcpSocketOptions.soBindToDevice.size())))
         ) [[unlikely]]
         {
            tcpSocketOperation.type = tcp_socket_operation_type::setopt_so_bindtodevice;
            handle_socket_error(tcpSocketOperation, errno);
            close(result);
            break;
         }
         assert(0 <= tcpSocketOptions.soKeepAlive);
         assert(1 >= tcpSocketOptions.soKeepAlive);
         if (
            true
            && (1 == tcpSocketOptions.soKeepAlive)
            && (-1 == setsockopt(result, SOL_SOCKET, SO_KEEPALIVE, std::addressof(tcpSocketOptions.soKeepAlive), sizeof(tcpSocketOptions.soKeepAlive)))
         ) [[unlikely]]
         {
            tcpSocketOperation.type = tcp_socket_operation_type::setopt_so_keepalive;
            handle_socket_error(tcpSocketOperation, errno);
            close(result);
            break;
         }
         if (
            true
            && (0 != tcpSocketOptions.ipTos)
            && (-1 == setsockopt(result, IPPROTO_IP, IP_TOS, std::addressof(tcpSocketOptions.ipTos), sizeof(tcpSocketOptions.ipTos)))
         ) [[unlikely]]
         {
            tcpSocketOperation.type = tcp_socket_operation_type::setopt_ip_tos;
            handle_socket_error(tcpSocketOperation, errno);
            close(result);
            break;
         }
         assert(0 <= tcpSocketOptions.tcpKeepCnt);
         if (
            true
            && (0 < tcpSocketOptions.tcpKeepCnt)
            && (-1 == setsockopt(result, IPPROTO_TCP, TCP_KEEPCNT, std::addressof(tcpSocketOptions.tcpKeepCnt), sizeof(tcpSocketOptions.tcpKeepCnt)))
         ) [[unlikely]]
         {
            tcpSocketOperation.type = tcp_socket_operation_type::setopt_tcp_keepcnt;
            handle_socket_error(tcpSocketOperation, errno);
            close(result);
            break;
         }
         assert(0 <= tcpSocketOptions.tcpKeepIdle);
         if (
            true
            && (0 < tcpSocketOptions.tcpKeepIdle)
            && (-1 == setsockopt(result, IPPROTO_TCP, TCP_KEEPIDLE, std::addressof(tcpSocketOptions.tcpKeepIdle), sizeof(tcpSocketOptions.tcpKeepIdle)))
         ) [[unlikely]]
         {
            tcpSocketOperation.type = tcp_socket_operation_type::setopt_tcp_keepidle;
            handle_socket_error(tcpSocketOperation, errno);
            close(result);
            break;
         }
         assert(0 <= tcpSocketOptions.tcpKeepIntvl);
         if (
            true
            && (0 < tcpSocketOptions.tcpKeepIntvl)
            && (-1 == setsockopt(result, IPPROTO_TCP, TCP_KEEPINTVL, std::addressof(tcpSocketOptions.tcpKeepIntvl), sizeof(tcpSocketOptions.tcpKeepIntvl)))
         ) [[unlikely]]
         {
            tcpSocketOperation.type = tcp_socket_operation_type::setopt_tcp_keepintvl;
            handle_socket_error(tcpSocketOperation, errno);
            close(result);
            break;
         }
         assert(0 <= tcpSocketOptions.tcpNoDelay);
         assert(1 >= tcpSocketOptions.tcpNoDelay);
         if (
            true
            && (1 == tcpSocketOptions.tcpNoDelay)
            && (-1 == setsockopt(result, IPPROTO_TCP, TCP_NODELAY, std::addressof(tcpSocketOptions.tcpNoDelay), sizeof(tcpSocketOptions.tcpNoDelay)))
         ) [[unlikely]]
         {
            tcpSocketOperation.type = tcp_socket_operation_type::setopt_tcp_nodelay;
            handle_socket_error(tcpSocketOperation, errno);
            close(result);
            break;
         }
         assert(0 <= tcpSocketOptions.tcpUserTimeout);
         if (0 < tcpSocketOptions.tcpUserTimeout)
         {
            if (-1 == setsockopt(result, IPPROTO_TCP, TCP_SYNCNT, std::addressof(m_tcpSynCnt), sizeof(m_tcpSynCnt))) [[unlikely]]
            {
               tcpSocketOperation.type = tcp_socket_operation_type::setopt_tcp_syncnt;
               handle_socket_error(tcpSocketOperation, errno);
               close(result);
               break;
            }
            if (-1 == setsockopt(result, IPPROTO_TCP, TCP_USER_TIMEOUT, std::addressof(tcpSocketOptions.tcpUserTimeout), sizeof(tcpSocketOptions.tcpUserTimeout))) [[unlikely]]
            {
               tcpSocketOperation.type = tcp_socket_operation_type::setopt_tcp_user_timeout;
               handle_socket_error(tcpSocketOperation, errno);
               close(result);
               break;
            }
         }
         m_tcpClientUring->register_tcp_socket(tcpSocketDescriptor, result);
         close(result);
         tcpSocketOperation.type = tcp_socket_operation_type::connect;
#endif
         m_tcpClientUring->prep_connect(tcpSocketOperation, tcpSocketOptions.address.ip);
      }
      break;

      case tcp_socket_operation_type::connect:
      {
         std::destroy_at(std::addressof(tcpSocketOptions));
         tcpSocketOperation.type = tcp_socket_operation_type::recv;
         tcpSocketDescriptor.tcpSocketStatus = tcp_socket_status::ready;
         tcpSocketDescriptor.tcpClient->io_connected();
         recv(tcpSocketOperation);
         send(tcpSocketDescriptor);
      }
      break;

      [[unlikely]] default:
      {
         log_error(std::source_location::current(), "[tcp_client] unexpected tcp_socket_operation_type {}: it must be a bug", to_underlying(tcpSocketOperation.type));
         unreachable();
      }
      break;
      }
   }

   void handle_deferred_task(tcp_deferred_task &deferredTask);

   void handle_event_completion() override
   {
      assert(std::this_thread::get_id() == m_threadId);
      m_uringCommandQueue.handle(*this);
   }

   void handle_ready_to_connect(tcp_client &tcpClient)
   {
      assert(nullptr == tcpClient.m_socketDescriptor);
      assert(nullptr == tcpClient.m_deferredTask);
      auto &tcpSocketDescriptor{pop_tcp_socket_descriptor(tcpClient),};
      assert(0 < tcpSocketDescriptor.registeredSocketIndex);
      assert(std::addressof(tcpSocketDescriptor) == tcpSocketDescriptor.tcpClient->m_socketDescriptor);
      auto &tcpSocketOperation{pop_tcp_socket_operation(tcpSocketDescriptor, tcp_socket_operation_type::socket),};
      assert(std::addressof(tcpSocketDescriptor) == tcpSocketOperation.descriptor);
      assert(1 == tcpSocketDescriptor.refsCount);
      auto config{tcpClient.io_ready_to_connect(),};
      auto &tcpSocketOptions = *std::construct_at(
         std::bit_cast<tcp_socket_options *>(std::addressof(tcpSocketOperation) + 1),
         tcp_socket_options
         {
            .soBindToDevice = {0,},
            .soKeepAlive = config.keep_alive().has_value() ? 1 : 0,
            .ipTos = to_underlying(config.quality_of_service()),
            .tcpKeepCnt = config.keep_alive().has_value() ? config.keep_alive().value().probesCount : 0,
            .tcpKeepIdle = static_cast<int>(config.keep_alive().has_value() ? config.keep_alive().value().idleTimeout.count() : 0),
            .tcpKeepIntvl = static_cast<int>(config.keep_alive().has_value() ? config.keep_alive().value().probeTimeout.count() : 0),
            .tcpNoDelay = config.nodelay() ? 1 : 0,
            .tcpUserTimeout = static_cast<int>(config.user_timeout().count()),
            .address = config.peer_address().socket_address()->sockaddr(),
         }
      );
      if (true == config.peer_address().network_interface().has_value())
      {
         auto const deviceName = config.peer_address().network_interface().value().system_name();
         std::memcpy(tcpSocketOptions.soBindToDevice.data(), deviceName.data(), deviceName.size());
         tcpSocketOptions.soBindToDevice[deviceName.size()] = 0;
      }
      m_tcpClientUring->prep_socket(tcpSocketOperation, tcpSocketOptions.address.addressFamily);
   }

   void handle_ready_to_disconnect(tcp_client &tcpClient)
   {
      assert(nullptr != tcpClient.m_socketDescriptor);
      assert(nullptr == tcpClient.m_deferredTask);
      auto *tcpSocketDescriptor{tcpClient.m_socketDescriptor,};
      if (nullptr != tcpSocketDescriptor) [[likely]]
      {
         assert(0 < tcpSocketDescriptor->registeredSocketIndex);
         assert(tcp_socket_status::none != tcpSocketDescriptor->tcpSocketStatus);
         assert(std::addressof(tcpClient) == tcpSocketDescriptor->tcpClient);
         assert(nullptr == tcpSocketDescriptor->next);
         if (tcp_socket_status::ready == tcpSocketDescriptor->tcpSocketStatus)
         {
            assert(1 == tcpSocketDescriptor->refsCount);
            auto &tcpSocketOperation{pop_tcp_socket_operation(*tcpSocketDescriptor, tcp_socket_operation_type::send),};
            assert(nullptr == tcpSocketOperation.next);
            assert(tcpSocketOperation.descriptor == tcpSocketDescriptor);
            assert(2 == tcpSocketDescriptor->refsCount);
            assert(0 == tcpSocketOperation.bufferOffset);
            assert(tcp_socket_operation_type::send == tcpSocketOperation.type);
            tcpSocketDescriptor->tcpSocketStatus = tcp_socket_status::close;
            prep_disconnect(tcpSocketOperation);
         }
         else if (tcp_socket_status::busy == tcpSocketDescriptor->tcpSocketStatus)
         {
            assert(2 == tcpSocketDescriptor->refsCount);
            tcpSocketDescriptor->tcpSocketStatus = tcp_socket_status::disconnect;
         }
      }
   }

   void handle_ready_to_send(tcp_client &tcpClient)
   {
      assert(nullptr == tcpClient.m_deferredTask);
      auto *tcpSocketDescriptor{tcpClient.m_socketDescriptor,};
      assert((nullptr == tcpSocketDescriptor) || (0 < tcpSocketDescriptor->registeredSocketIndex));
      assert((nullptr == tcpSocketDescriptor) || (tcp_socket_status::none != tcpSocketDescriptor->tcpSocketStatus));
      assert((nullptr == tcpSocketDescriptor) || (tcp_socket_status::connect != tcpSocketDescriptor->tcpSocketStatus));
      assert((nullptr == tcpSocketDescriptor) || (std::addressof(tcpClient) == tcpSocketDescriptor->tcpClient));
      assert((nullptr == tcpSocketDescriptor) || (nullptr == tcpSocketDescriptor->next));
      if ((nullptr != tcpSocketDescriptor) && (tcp_socket_status::ready == tcpSocketDescriptor->tcpSocketStatus))
      {
         assert(1 == tcpSocketDescriptor->refsCount);
         send(*tcpSocketDescriptor);
      }
   }

   void handle_received_data(tcp_socket_operation &tcpSocketOperation, size_t const bytesReceived)
   {
      assert(nullptr == tcpSocketOperation.next);
      assert(nullptr != tcpSocketOperation.descriptor);
      auto &tcpSocketDescriptor{*tcpSocketOperation.descriptor,};
      assert(tcp_socket_status::none != tcpSocketDescriptor.tcpSocketStatus);
      assert(tcp_socket_status::connect != tcpSocketDescriptor.tcpSocketStatus);
      assert(nullptr != tcpSocketDescriptor.tcpClient);
      assert(tcpSocketOperation.descriptor == tcpSocketDescriptor.tcpClient->m_socketDescriptor);
      assert(nullptr == tcpSocketDescriptor.next);
      assert(tcp_socket_operation_type::recv == tcpSocketOperation.type);
      assert(0 < bytesReceived);
      auto const bufferCapacity{m_tcpClientUring->registered_buffer_capacity(tcpSocketOperation),};
      size_t const bytesLength{tcpSocketOperation.bufferOffset + bytesReceived,};
      if (bufferCapacity < bytesLength) [[unlikely]]
      {
         log_error(std::source_location::current(), "[tcp_client] received more bytes than the buffer contains: it must be a bug");
         unreachable();
      }
      size_t bytesProcessed{static_cast<size_t>(-1),};
      if (
         auto const errorCode
         {
            tcpSocketDescriptor.tcpClient->io_data_received(
               data_chunk
               {
                  .bytes = std::addressof(tcpSocketOperation.bufferBytes[0]),
                  .bytesLength = bytesLength,
               },
               bytesProcessed
            ),
         };
         false == bool{errorCode}
      ) [[likely]]
      {
         assert(static_cast<size_t>(-1) != bytesProcessed);
         if (bytesProcessed < bytesLength)
         {
            tcpSocketOperation.bufferOffset = bytesLength - bytesProcessed;
            if (bufferCapacity <= tcpSocketOperation.bufferOffset) [[unlikely]]
            {
               log_error(std::source_location::current(), "[tcp_client] no more bytes could be received: it must be a bug");
               unreachable();
            }
            if (0 < bytesProcessed)
            {
               std::memmove(
                  std::addressof(tcpSocketOperation.bufferBytes[0]),
                  std::addressof(tcpSocketOperation.bufferBytes[0]) + bytesProcessed,
                  tcpSocketOperation.bufferOffset
               );
            }
         }
         else if (bytesProcessed == bytesLength)
         {
            tcpSocketOperation.bufferOffset = 0;
         }
         else [[unlikely]]
         {
            log_error(std::source_location::current(), "[tcp_client] processed more bytes than received: it must be a bug");
            unreachable();
         }
         recv(tcpSocketOperation);
      }
      else if (tcp_socket_status::ready == tcpSocketDescriptor.tcpSocketStatus)
      {
         assert(1 == tcpSocketDescriptor.refsCount);
         assert(false == (bool{tcpSocketDescriptor.disconnectReason}));
         tcpSocketDescriptor.tcpSocketStatus = tcp_socket_status::close;
         tcpSocketDescriptor.disconnectReason = errorCode;
         prep_disconnect(tcpSocketOperation);
      }
      else if (tcp_socket_status::busy == tcpSocketDescriptor.tcpSocketStatus)
      {
         assert(2 == tcpSocketDescriptor.refsCount);
         assert(false == (bool{tcpSocketDescriptor.disconnectReason,}));
         tcpSocketDescriptor.tcpSocketStatus = tcp_socket_status::disconnect;
         tcpSocketDescriptor.disconnectReason = errorCode;
         push_tcp_socket_operation(tcpSocketOperation);
         assert(1 == tcpSocketDescriptor.refsCount);
      }
      else
      {
         assert(
            false
            || (tcp_socket_status::disconnect == tcpSocketDescriptor.tcpSocketStatus)
            || (tcp_socket_status::close == tcpSocketDescriptor.tcpSocketStatus)
         );
         push_tcp_socket_operation(tcpSocketOperation);
      }
   }

   void handle_send_completion(tcp_socket_operation &tcpSocketOperation)
   {
      assert(nullptr == tcpSocketOperation.next);
      assert(nullptr != tcpSocketOperation.descriptor);
      auto &tcpSocketDescriptor{*tcpSocketOperation.descriptor,};
      assert(0 < tcpSocketDescriptor.registeredSocketIndex);
      assert(tcp_socket_status::none != tcpSocketDescriptor.tcpSocketStatus);
      assert(tcp_socket_status::connect!= tcpSocketDescriptor.tcpSocketStatus);
      assert(tcp_socket_status::ready != tcpSocketDescriptor.tcpSocketStatus);
      assert(nullptr != tcpSocketDescriptor.tcpClient);
      assert(tcpSocketOperation.descriptor == tcpSocketDescriptor.tcpClient->m_socketDescriptor);
      assert(nullptr == tcpSocketDescriptor.next);
      assert(0 == tcpSocketOperation.bufferOffset);
      assert(tcp_socket_operation_type::send == tcpSocketOperation.type);
      if (tcp_socket_status::busy == tcpSocketDescriptor.tcpSocketStatus) [[likely]]
      {
         assert(2 == tcpSocketDescriptor.refsCount);
         tcpSocketDescriptor.tcpSocketStatus = tcp_socket_status::ready;
         push_tcp_socket_operation(tcpSocketOperation);
         assert(1 == tcpSocketDescriptor.refsCount);
         send(tcpSocketDescriptor);
      }
      else if (tcp_socket_status::disconnect == tcpSocketDescriptor.tcpSocketStatus)
      {
         tcpSocketDescriptor.tcpSocketStatus = tcp_socket_status::close;
         prep_disconnect(tcpSocketOperation);
      }
      else
      {
         assert(tcp_socket_status::close == tcpSocketDescriptor.tcpSocketStatus);
         push_tcp_socket_operation(tcpSocketOperation);
      }
   }

   void handle_socket_error(tcp_socket_operation &tcpSocketOperation, int32_t const value)
   {
      assert(nullptr == tcpSocketOperation.next);
      assert(nullptr != tcpSocketOperation.descriptor);
      auto &tcpSocketDescriptor{*tcpSocketOperation.descriptor,};
      assert(0 < tcpSocketDescriptor.registeredSocketIndex);
      assert(tcp_socket_status::none != tcpSocketDescriptor.tcpSocketStatus);
      assert(nullptr != tcpSocketDescriptor.tcpClient);
      assert(tcpSocketOperation.descriptor == tcpSocketDescriptor.tcpClient->m_socketDescriptor);
      assert(nullptr == tcpSocketDescriptor.next);
      assert(tcp_socket_operation_type::none != tcpSocketOperation.type);
      assert(0 < value);
      switch (tcpSocketOperation.type)
      {
      [[unlikely]] case tcp_socket_operation_type::none: unreachable();

      case tcp_socket_operation_type::socket: [[fallthrough]];
      case tcp_socket_operation_type::setopt_so_bindtodevice: [[fallthrough]];
      case tcp_socket_operation_type::setopt_so_keepalive: [[fallthrough]];
      case tcp_socket_operation_type::setopt_ip_tos: [[fallthrough]];
      case tcp_socket_operation_type::setopt_tcp_keepcnt: [[fallthrough]];
      case tcp_socket_operation_type::setopt_tcp_keepidle: [[fallthrough]];
      case tcp_socket_operation_type::setopt_tcp_keepintvl: [[fallthrough]];
      case tcp_socket_operation_type::setopt_tcp_nodelay: [[fallthrough]];
      case tcp_socket_operation_type::setopt_tcp_syncnt: [[fallthrough]];
      case tcp_socket_operation_type::setopt_tcp_user_timeout: [[fallthrough]];
      case tcp_socket_operation_type::connect:
      {
         assert(tcp_socket_status::ready != tcpSocketDescriptor.tcpSocketStatus);
         assert(tcp_socket_status::busy != tcpSocketDescriptor.tcpSocketStatus);
         assert(tcp_socket_status::close != tcpSocketDescriptor.tcpSocketStatus);
         assert(1 == tcpSocketDescriptor.refsCount);
         assert(false == (bool{tcpSocketDescriptor.disconnectReason,}));
         assert(0 == tcpSocketOperation.bufferOffset);
         tcpSocketDescriptor.tcpSocketStatus = tcp_socket_status::close;
         tcpSocketDescriptor.disconnectReason = std::error_code{value, std::generic_category(),};
         log_socket_error(tcpSocketOperation.type, tcpSocketDescriptor.disconnectReason);
         std::destroy_at(std::bit_cast<tcp_socket_options *>(std::addressof(tcpSocketOperation) + 1));
#if ((2 < IO_URING_VERSION_MAJOR) || ((2 == IO_URING_VERSION_MAJOR) && (6 <= IO_URING_VERSION_MINOR)))
         if (tcp_socket_operation_type::socket == tcpSocketOperation.type)
#else
         if (tcp_socket_operation_type::connect != tcpSocketOperation.type)
#endif
         {
            push_tcp_socket_operation(tcpSocketOperation);
         }
         else
         {
            prep_close(tcpSocketOperation);
         }
      }
      break;

      case tcp_socket_operation_type::recv:
      {
         if (
            false
            || (tcp_socket_status::ready == tcpSocketDescriptor.tcpSocketStatus)
            || (tcp_socket_status::busy == tcpSocketDescriptor.tcpSocketStatus)
         )
         {
            assert(
               false
               || ((tcp_socket_status::ready == tcpSocketDescriptor.tcpSocketStatus) && (1 == tcpSocketDescriptor.refsCount))
               || ((tcp_socket_status::busy == tcpSocketDescriptor.tcpSocketStatus) && (2 == tcpSocketDescriptor.refsCount))
            );
            assert(false == (bool{tcpSocketDescriptor.disconnectReason}));
            tcpSocketDescriptor.tcpSocketStatus = tcp_socket_status::close;
            tcpSocketDescriptor.disconnectReason = std::error_code{value, std::generic_category(),};
            log_socket_error(tcpSocketOperation.type, tcpSocketDescriptor.disconnectReason);
            prep_close(tcpSocketOperation);
         }
         else
         {
            assert(
               false
               || (tcp_socket_status::disconnect == tcpSocketDescriptor.tcpSocketStatus)
               || (tcp_socket_status::close == tcpSocketDescriptor.tcpSocketStatus)
            );
            push_tcp_socket_operation(tcpSocketOperation);
         }
      }
      break;

      case tcp_socket_operation_type::send:
      {
         if (
            false
            || (tcp_socket_status::busy == tcpSocketDescriptor.tcpSocketStatus)
            || (tcp_socket_status::disconnect == tcpSocketDescriptor.tcpSocketStatus)
         )
         {
            assert(false == (bool{tcpSocketDescriptor.disconnectReason}));
            tcpSocketDescriptor.tcpSocketStatus = tcp_socket_status::close;
            tcpSocketDescriptor.disconnectReason = std::error_code{value, std::generic_category(),};
            log_socket_error(tcpSocketOperation.type, tcpSocketDescriptor.disconnectReason);
            prep_close(tcpSocketOperation);
         }
         else
         {
            assert(tcp_socket_status::close == tcpSocketDescriptor.tcpSocketStatus);
            push_tcp_socket_operation(tcpSocketOperation);
         }
      }
      break;

      case tcp_socket_operation_type::disconnect: [[fallthrough]];
      case tcp_socket_operation_type::shutdown:
      {
         assert(tcp_socket_status::close == tcpSocketDescriptor.tcpSocketStatus);
         assert(0 == tcpSocketOperation.bufferOffset);
         log_socket_error(tcpSocketOperation.type, std::error_code{value, std::generic_category(),});
         prep_close(tcpSocketOperation);
      }
      break;

      case tcp_socket_operation_type::close:
      {
         assert(tcp_socket_status::close == tcpSocketDescriptor.tcpSocketStatus);
         assert(0 == tcpSocketOperation.bufferOffset);
         log_socket_error(tcpSocketOperation.type, std::error_code{value, std::generic_category(),});
         push_tcp_socket_operation(tcpSocketOperation);
      }
      break;
      }
   }

   void handle_task_completion(intptr_t const userdata, int32_t const result, uint32_t const flags) override
   {
      assert(0 != userdata);
      auto &tcpSocketOperation{*std::launder(std::bit_cast<tcp_socket_operation *>(userdata)),};
      assert(nullptr == tcpSocketOperation.next);
      assert(nullptr != tcpSocketOperation.descriptor);
      assert(tcp_socket_status::none != tcpSocketOperation.descriptor->tcpSocketStatus);
      assert(0 < tcpSocketOperation.descriptor->refsCount);
      assert(nullptr == tcpSocketOperation.descriptor->next);
      assert(tcp_socket_operation_type::none != tcpSocketOperation.type);
      assert(std::this_thread::get_id() == m_threadId);
      if (0 > result) [[unlikely]]
      {
         if (IORING_CQE_F_MORE == (IORING_CQE_F_MORE & flags))
         {
            assert(IORING_CQE_F_MORE == flags);
         }
         else
         {
            assert((0 == flags) || (IORING_CQE_F_NOTIF == flags));
            handle_socket_error(tcpSocketOperation, -result);
         }
         return;
      }
      switch (tcpSocketOperation.type)
      {
      [[unlikely]] case tcp_socket_operation_type::none: break;
      case tcp_socket_operation_type::socket: [[fallthrough]];
      case tcp_socket_operation_type::setopt_so_bindtodevice: [[fallthrough]];
      case tcp_socket_operation_type::setopt_so_keepalive: [[fallthrough]];
      case tcp_socket_operation_type::setopt_ip_tos: [[fallthrough]];
      case tcp_socket_operation_type::setopt_tcp_keepcnt: [[fallthrough]];
      case tcp_socket_operation_type::setopt_tcp_keepidle: [[fallthrough]];
      case tcp_socket_operation_type::setopt_tcp_keepintvl: [[fallthrough]];
      case tcp_socket_operation_type::setopt_tcp_nodelay: [[fallthrough]];
      case tcp_socket_operation_type::setopt_tcp_syncnt: [[fallthrough]];
      case tcp_socket_operation_type::setopt_tcp_user_timeout: [[fallthrough]];
      case tcp_socket_operation_type::connect:
      {
         handle_connect_completion(tcpSocketOperation, result, flags);
      }
      break;

      case tcp_socket_operation_type::recv:
      {
         assert(0 == flags);
         if (0 < result) [[likely]]
         {
            handle_received_data(tcpSocketOperation, static_cast<size_t>(result));
         }
         else
         {
            assert(0 == result);
            handle_socket_error(tcpSocketOperation, to_underlying(std::errc::connection_reset));
         }
      }
      break;

      case tcp_socket_operation_type::send:
      {
         if (IORING_CQE_F_MORE == (IORING_CQE_F_MORE & flags))
         {
            assert(IORING_CQE_F_MORE == flags);
         }
         else
         {
            assert(IORING_CQE_F_NOTIF == flags);
            handle_send_completion(tcpSocketOperation);
         }
      }
      break;

      case tcp_socket_operation_type::disconnect:
      {
         assert(tcp_socket_status::close == tcpSocketOperation.descriptor->tcpSocketStatus);
         if (IORING_CQE_F_MORE == (IORING_CQE_F_MORE & flags))
         {
            assert(IORING_CQE_F_MORE == flags);
         }
         else
         {
            assert(IORING_CQE_F_NOTIF == flags);
            prep_shutdown(tcpSocketOperation);
         }
      }
      break;

      case tcp_socket_operation_type::shutdown:
      {
         assert(tcp_socket_status::close == tcpSocketOperation.descriptor->tcpSocketStatus);
         assert(0 == flags);
         prep_close(tcpSocketOperation);
      }
      break;

      case tcp_socket_operation_type::close:
      {
         assert(tcp_socket_status::close == tcpSocketOperation.descriptor->tcpSocketStatus);
         assert(0 == flags);
         push_tcp_socket_operation(tcpSocketOperation);
      }
      break;
      }
   }

   void handle_thread_task(thread_task &task)
   {
      assert(task.routine);
      task.routine();
      task.completionPromise.set_value();
   }

   [[nodiscard]] tcp_socket_descriptor &pop_tcp_socket_descriptor(tcp_client &tcpClient)
   {
      assert(nullptr == tcpClient.m_socketDescriptor);
      assert(nullptr == tcpClient.m_deferredTask);
      if (nullptr == m_tcpSocketDescriptors) [[unlikely]]
      {
         log_error(std::source_location::current(), "[tcp_client] too few socket descriptors provided, please increase capacity of socket descriptor list");
         unreachable();
      }
      auto &tcpSocketDescriptor{*std::launder(m_tcpSocketDescriptors),};
      assert(tcp_socket_status::none == tcpSocketDescriptor.tcpSocketStatus);
      assert(0 == tcpSocketDescriptor.refsCount);
      assert(nullptr == tcpSocketDescriptor.tcpClient);
      assert(false == (bool{tcpSocketDescriptor.disconnectReason,}));
      m_tcpSocketDescriptors = std::launder(tcpSocketDescriptor.next);
      tcpSocketDescriptor.tcpSocketStatus = tcp_socket_status::connect;
      tcpSocketDescriptor.tcpClient = std::addressof(tcpClient);
      tcpSocketDescriptor.next = nullptr;
      tcpClient.m_socketDescriptor = std::addressof(tcpSocketDescriptor);
      return tcpSocketDescriptor;
   }

   [[nodiscard]] tcp_socket_operation &pop_tcp_socket_operation(
      tcp_socket_descriptor &tcpSocketDescriptor,
      tcp_socket_operation_type const tcpSocketOperationType
   )
   {
      assert(
         false
         || ((tcp_socket_operation_type::socket == tcpSocketOperationType) && (tcp_socket_status::connect == tcpSocketDescriptor.tcpSocketStatus))
         || ((tcp_socket_operation_type::send == tcpSocketOperationType) && (tcp_socket_status::ready == tcpSocketDescriptor.tcpSocketStatus))
      );
      assert(2 > tcpSocketDescriptor.refsCount);
      assert(nullptr != tcpSocketDescriptor.tcpClient);
      assert(std::addressof(tcpSocketDescriptor) == tcpSocketDescriptor.tcpClient->m_socketDescriptor);
      if (nullptr == m_tcpSocketOperations) [[unlikely]]
      {
         log_error(std::source_location::current(), "[tcp_client] too few socket operations provided, it must be a bug");
         unreachable();
      }
      auto &tcpSocketOperation{*std::launder(m_tcpSocketOperations),};
      assert(nullptr == tcpSocketOperation.descriptor);
      assert(0 == tcpSocketOperation.bufferOffset);
      assert(tcp_socket_operation_type::none == tcpSocketOperation.type);
      m_tcpSocketOperations = std::launder(tcpSocketOperation.next);
      tcpSocketOperation.next = nullptr;
      tcpSocketOperation.descriptor = std::addressof(tcpSocketDescriptor);
      tcpSocketOperation.type = tcpSocketOperationType;
      ++tcpSocketDescriptor.refsCount;
      return tcpSocketOperation;
   }

   void prep_close(tcp_socket_operation &tcpSocketOperation)
   {
      assert(nullptr != tcpSocketOperation.descriptor);
      assert(tcp_socket_status::close == tcpSocketOperation.descriptor->tcpSocketStatus);
      tcpSocketOperation.type = tcp_socket_operation_type::close;
      m_tcpClientUring->prep_close(tcpSocketOperation);
   }

   void prep_disconnect(tcp_socket_operation &tcpSocketOperation)
   {
      assert(nullptr == tcpSocketOperation.next);
      assert(nullptr != tcpSocketOperation.descriptor);
      auto &tcpSocketDescriptor{*tcpSocketOperation.descriptor,};
      assert(0 < tcpSocketDescriptor.registeredSocketIndex);
      assert(tcp_socket_status::close == tcpSocketDescriptor.tcpSocketStatus);
      assert(nullptr != tcpSocketDescriptor.tcpClient);
      assert(tcpSocketOperation.descriptor == tcpSocketDescriptor.tcpClient->m_socketDescriptor);
      assert(nullptr == tcpSocketDescriptor.next);
      assert(tcp_socket_operation_type::none != tcpSocketOperation.type);
      assert(tcp_socket_operation_type::socket != tcpSocketOperation.type);
      assert(tcp_socket_operation_type::setopt_so_bindtodevice != tcpSocketOperation.type);
      assert(tcp_socket_operation_type::setopt_so_keepalive != tcpSocketOperation.type);
      assert(tcp_socket_operation_type::setopt_ip_tos != tcpSocketOperation.type);
      assert(tcp_socket_operation_type::setopt_tcp_keepcnt != tcpSocketOperation.type);
      assert(tcp_socket_operation_type::setopt_tcp_keepidle != tcpSocketOperation.type);
      assert(tcp_socket_operation_type::setopt_tcp_keepintvl != tcpSocketOperation.type);
      assert(tcp_socket_operation_type::setopt_tcp_nodelay != tcpSocketOperation.type);
      assert(tcp_socket_operation_type::setopt_tcp_syncnt != tcpSocketOperation.type);
      assert(tcp_socket_operation_type::setopt_tcp_user_timeout != tcpSocketOperation.type);
      assert(tcp_socket_operation_type::connect != tcpSocketOperation.type);
      assert(tcp_socket_operation_type::disconnect != tcpSocketOperation.type);
      assert(tcp_socket_operation_type::close != tcpSocketOperation.type);
      size_t bytesWritten{static_cast<size_t>(-1),};
      if (
         auto const errorCode
         {
            tcpSocketDescriptor.tcpClient->io_data_to_shutdown(
               data_chunk
               {
                  .bytes = std::addressof(tcpSocketOperation.bufferBytes[0]),
                  .bytesLength = m_tcpClientUring->registered_buffer_capacity(tcpSocketOperation)
               },
               bytesWritten
            ),
         };
         (false == bool{errorCode}) && (0 < bytesWritten)
      )
      {
         assert(static_cast<size_t>(-1) != bytesWritten);
         tcpSocketOperation.type = tcp_socket_operation_type::disconnect;
         m_tcpClientUring->prep_send(tcpSocketOperation, bytesWritten);
      }
      else
      {
         prep_shutdown(tcpSocketOperation);
      }
   }

   void prep_shutdown(tcp_socket_operation &tcpSocketOperation)
   {
      assert(nullptr != tcpSocketOperation.descriptor);
      assert(tcp_socket_status::close == tcpSocketOperation.descriptor->tcpSocketStatus);
      if (1 == tcpSocketOperation.descriptor->refsCount)
      {
         prep_close(tcpSocketOperation);
      }
      else
      {
         assert(2 == tcpSocketOperation.descriptor->refsCount);
         tcpSocketOperation.type = tcp_socket_operation_type::shutdown;
         m_tcpClientUring->prep_shutdown(tcpSocketOperation, SHUT_RDWR);
      }
   }

   void process_deferred_tasks();

   void push_tcp_socket_descriptor(tcp_socket_descriptor &tcpSocketDescriptor)
   {
      assert(tcp_socket_status::close == tcpSocketDescriptor.tcpSocketStatus);
      assert(0 == tcpSocketDescriptor.refsCount);
      assert(nullptr != tcpSocketDescriptor.tcpClient);
      auto &tcpClient{*tcpSocketDescriptor.tcpClient,};
      assert(std::addressof(tcpSocketDescriptor) == tcpClient.m_socketDescriptor);
      cancel_deferred_task(tcpClient);
      assert(nullptr == tcpSocketDescriptor.next);
      tcpSocketDescriptor.tcpSocketStatus = tcp_socket_status::none;
      tcpSocketDescriptor.refsCount = 0;
      tcpClient.m_socketDescriptor = nullptr;
      tcpSocketDescriptor.tcpClient = nullptr;
      tcpSocketDescriptor.next = std::launder(m_tcpSocketDescriptors);
      auto const disconnectReason{tcpSocketDescriptor.disconnectReason,};
      tcpSocketDescriptor.disconnectReason = std::error_code{};
      m_tcpSocketDescriptors = std::launder(std::addressof(tcpSocketDescriptor));
      tcpClient.io_disconnected(disconnectReason);
   }

   void push_tcp_socket_operation(tcp_socket_operation &tcpSocketOperation)
   {
      assert(nullptr == tcpSocketOperation.next);
      assert(nullptr != tcpSocketOperation.descriptor);
      auto &tcpSocketDescriptor{*tcpSocketOperation.descriptor,};
      assert(0 < tcpSocketDescriptor.registeredSocketIndex);
      assert(tcp_socket_status::none != tcpSocketDescriptor.tcpSocketStatus);
      assert(tcp_socket_status::busy != tcpSocketDescriptor.tcpSocketStatus);
      assert(nullptr != tcpSocketDescriptor.tcpClient);
      assert(tcpSocketOperation.descriptor == tcpSocketDescriptor.tcpClient->m_socketDescriptor);
      assert(nullptr == tcpSocketDescriptor.next);
      assert(tcp_socket_operation_type::none != tcpSocketOperation.type);
      tcpSocketOperation.next = std::launder(m_tcpSocketOperations);
      tcpSocketOperation.descriptor = nullptr;
      tcpSocketOperation.bufferOffset = 0;
      tcpSocketOperation.type = tcp_socket_operation_type::none;
      m_tcpSocketOperations = std::launder(std::addressof(tcpSocketOperation));
      if (0 == --tcpSocketDescriptor.refsCount)
      {
         push_tcp_socket_descriptor(tcpSocketDescriptor);
      }
   }

   void recv(tcp_socket_operation &tcpSocketOperation)
   {
      assert(nullptr == tcpSocketOperation.next);
      assert(nullptr != tcpSocketOperation.descriptor);
      assert(0 < tcpSocketOperation.descriptor->registeredSocketIndex);
      assert(tcp_socket_status::none != tcpSocketOperation.descriptor->tcpSocketStatus);
      assert(tcp_socket_status::connect != tcpSocketOperation.descriptor->tcpSocketStatus);
      assert(nullptr != tcpSocketOperation.descriptor->tcpClient);
      assert(tcpSocketOperation.descriptor == tcpSocketOperation.descriptor->tcpClient->m_socketDescriptor);
      assert(nullptr == tcpSocketOperation.descriptor->next);
      assert(tcp_socket_operation_type::recv == tcpSocketOperation.type);
      m_tcpClientUring->prep_recv(tcpSocketOperation);
   }

   void send(tcp_socket_descriptor &tcpSocketDescriptor)
   {
      assert(0 < tcpSocketDescriptor.registeredSocketIndex);
      assert(tcp_socket_status::ready == tcpSocketDescriptor.tcpSocketStatus);
      assert(1 == tcpSocketDescriptor.refsCount);
      assert(nullptr != tcpSocketDescriptor.tcpClient);
      auto &tcpClient{*tcpSocketDescriptor.tcpClient,};
      assert(std::addressof(tcpSocketDescriptor) == tcpClient.m_socketDescriptor);
      assert(nullptr == tcpSocketDescriptor.next);
      cancel_deferred_task(tcpClient);
      auto &tcpSocketOperation{pop_tcp_socket_operation(tcpSocketDescriptor, tcp_socket_operation_type::send),};
      assert(2 == tcpSocketDescriptor.refsCount);
      size_t bytesWritten{static_cast<size_t>(-1),};
      if (
         auto const errorCode
         {
            tcpClient.io_data_to_send(
               data_chunk
               {
                  .bytes = std::addressof(tcpSocketOperation.bufferBytes[0]),
                  .bytesLength = m_tcpClientUring->registered_buffer_capacity(tcpSocketOperation),
               },
               bytesWritten
            ),
         };
         false == bool{errorCode,}
      ) [[likely]]
      {
         assert(static_cast<size_t>(-1) != bytesWritten);
         if (0 == bytesWritten)
         {
            push_tcp_socket_operation(tcpSocketOperation);
            assert(1 == tcpSocketDescriptor.refsCount);
            return;
         }
         tcpSocketDescriptor.tcpSocketStatus = tcp_socket_status::busy;
         m_tcpClientUring->prep_send(tcpSocketOperation, bytesWritten);
      }
      else
      {
         assert(1 == tcpSocketDescriptor.refsCount);
         assert(false == (bool{tcpSocketDescriptor.disconnectReason}));
         tcpSocketDescriptor.tcpSocketStatus = tcp_socket_status::close;
         tcpSocketDescriptor.disconnectReason = errorCode;
         prep_disconnect(tcpSocketOperation);
      }
   }
};

}
