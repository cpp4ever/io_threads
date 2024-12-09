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

#include <netinet/tcp.h>

#include <algorithm> ///< for std::max
#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <chrono> ///< for std::chrono::milliseconds
#include <cstddef> ///< for size_t, std::byte
#include <cstdint> ///< for uint16_t
#include <cstring> ///< for std::memcpy
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
            tcp_client_thread_worker threadWorker{coreCpuId, stopToken, capacityOfSocketDescriptorList, capacityOfInputOutputBuffer,};
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
   int const m_soIncomingCpu{0,};
   int const m_tcpSynCnt{1,};

   [[nodiscard]] tcp_client_thread_worker(
      uint16_t const coreCpuId,
      std::stop_token const &stopToken,
      size_t const capacityOfSocketDescriptorList,
      size_t const capacityOfInputOutputBuffer
   ) :
      m_uringWorker{std::make_unique<uring_worker>(coreCpuId, capacityOfSocketDescriptorList * 2 + 1),},
      m_uringStopToken{stopToken,},
      m_uringCommandQueue{capacityOfSocketDescriptorList,},
      m_soIncomingCpu{coreCpuId,}
   {
      assert(0 < capacityOfInputOutputBuffer);
      m_tcpSocketOperations = m_uringWorker->register_tcp_socket_operations(
         capacityOfSocketDescriptorList * 2,
         std::max(sizeof(tcp_socket_operation) + sizeof(tcp_socket_options), tcp_socket_operation::total_size(capacityOfInputOutputBuffer))
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
      auto &tcpSocketOperation{*std::launder(std::bit_cast<tcp_socket_operation *>(userdata)),};
      assert(nullptr == tcpSocketOperation.next);
      assert(nullptr != tcpSocketOperation.descriptor);
      assert(tcp_socket_status::none != tcpSocketOperation.descriptor->tcpSocketStatus);
      assert(nullptr == tcpSocketOperation.descriptor->next);
      assert(tcp_socket_operation_type::none != tcpSocketOperation.type);
      switch (tcpSocketOperation.type)
      {
      case tcp_socket_operation_type::socket: [[fallthrough]];
      case tcp_socket_operation_type::setopt_so_bindtodevice: [[fallthrough]];
      case tcp_socket_operation_type::setopt_so_incoming_cpu: [[fallthrough]];
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
         handle_recv_completion(tcpSocketOperation, result, flags);
      }
      break;

      case tcp_socket_operation_type::send:
      {
         handle_send_completion(tcpSocketOperation, result, flags);
      }
      break;

      case tcp_socket_operation_type::disconnect: [[fallthrough]];
      case tcp_socket_operation_type::close:
      {
         handle_disconnect_completion(tcpSocketOperation, result, flags);
      }
      break;

      [[unlikely]] default:
      {
         log_error(std::source_location::current(), "[tcp_client] unexpected tcp_socket_operation_type {}: it must be a bug", to_underlying(tcpSocketOperation.type));
         unreachable();
      }
      }
      m_uringStopToken.decrement_tasks_count();
   }

   void prep_sockopt_direct(tcp_socket_operation &tcpSocketOperation, int const level, int const optname, void *optval, int const optlen)
   {
      auto &submissionQueueEntry = m_uringWorker->submission_entry(std::addressof(tcpSocketOperation));
      io_uring_prep_cmd_sock(
         std::addressof(submissionQueueEntry),
         SOCKET_URING_OP_SETSOCKOPT,
         tcpSocketOperation.descriptor->registeredTcpSocketIndex,
         level,
         optname,
         optval,
         optlen
      );
      submissionQueueEntry.flags |= IOSQE_FIXED_FILE;
      m_uringStopToken.increment_tasks_count();
   }

   void prep_sockopt_direct(tcp_socket_operation &tcpSocketOperation, int const level, int const optname, int const optval)
   {
      prep_sockopt_direct(tcpSocketOperation, level, optname, std::bit_cast<void *>(std::addressof(optval)), sizeof(optval));
   }

   void handle_connect_completion(tcp_socket_operation &tcpSocketOperation, int32_t result, [[maybe_unused]] uint32_t const flags)
   {
      assert(nullptr == tcpSocketOperation.next);
      assert(nullptr != tcpSocketOperation.descriptor);
      assert(tcp_socket_status::connecting == tcpSocketOperation.descriptor->tcpSocketStatus);
      assert(false == tcpSocketOperation.descriptor->disconnectOnCompletion);
      assert(nullptr != tcpSocketOperation.descriptor->tcpClient);
      assert(nullptr == tcpSocketOperation.descriptor->next);
      assert(0 == tcpSocketOperation.bufferOffset);
      assert(tcp_socket_operation_type::none != tcpSocketOperation.type);
      assert(0 == flags);
      auto &tcpSocketDescriptor = *tcpSocketOperation.descriptor;
      auto &tcpSocketOptions = *std::bit_cast<tcp_socket_options *>(std::addressof(tcpSocketOperation) + 1);
      if (true == tcpSocketDescriptor.disconnectOnCompletion) [[unlikely]]
      {
         std::destroy_at(std::addressof(tcpSocketOptions));
         handle_disconnect(tcpSocketOperation, std::error_code{});
         return;
      }
      switch (tcpSocketOperation.type)
      {
      case tcp_socket_operation_type::socket:
      {
         if (0 > result) [[unlikely]]
         {
            std::error_code const errorCode{-result, std::generic_category(),};
            log_system_error(std::source_location::current(), "[tcp_thread] failed to create TCP socket: ({}) - {}", errorCode);
            handle_disconnect(tcpSocketOperation, errorCode);
            break;
         }
         if (0 != tcpSocketOptions.soBindToDevice[0])
         {
            tcpSocketOperation.type = tcp_socket_operation_type::setopt_so_bindtodevice;
            prep_sockopt_direct(
               tcpSocketOperation,
               SOL_SOCKET,
               SO_BINDTODEVICE,
               tcpSocketOptions.soBindToDevice.data(),
               std::strlen(tcpSocketOptions.soBindToDevice.data())
            );
            break;
         }
      } [[fallthrough]];
      case tcp_socket_operation_type::setopt_so_bindtodevice:
      {
         if (0 > result) [[unlikely]]
         {
            std::error_code const errorCode{-result, std::generic_category(),};
            log_system_error(std::source_location::current(), "[tcp_thread] failed to set SO_BINDTODEVICE socket option: ({}) - {}", errorCode);
            handle_disconnect(tcpSocketOperation, errorCode);
            break;
         }
         tcpSocketOperation.type = tcp_socket_operation_type::setopt_so_incoming_cpu;
         prep_sockopt_direct(tcpSocketOperation, SOL_SOCKET, SO_INCOMING_CPU, m_soIncomingCpu);
      }
      break;

      case tcp_socket_operation_type::setopt_so_incoming_cpu:
      {
         if (0 > result) [[unlikely]]
         {
            log_system_error(std::source_location::current(), "[tcp_thread] failed to set SO_INCOMING_CPU socket option: ({}) - {}", -result);
            result = 0;
         }
         if (1 == tcpSocketOptions.soKeepAlive)
         {
            tcpSocketOperation.type = tcp_socket_operation_type::setopt_so_keepalive;
            prep_sockopt_direct(tcpSocketOperation, SOL_SOCKET, SO_KEEPALIVE, tcpSocketOptions.soKeepAlive);
            break;
         }
         else
         {
            assert(0 == tcpSocketOptions.soKeepAlive);
         }
      } [[fallthrough]];
      case tcp_socket_operation_type::setopt_so_keepalive:
      {
         if (0 > result) [[unlikely]]
         {
            std::error_code const errorCode{-result, std::generic_category(),};
            log_system_error(std::source_location::current(), "[tcp_thread] failed to set SO_KEEPALIVE socket option: ({}) - {}", errorCode);
            handle_disconnect(tcpSocketOperation, errorCode);
            break;
         }
         if (0 != tcpSocketOptions.ipTos)
         {
            tcpSocketOperation.type = tcp_socket_operation_type::setopt_ip_tos;
            prep_sockopt_direct(tcpSocketOperation, IPPROTO_IP, IP_TOS, tcpSocketOptions.ipTos);
            break;
         }
      } [[fallthrough]];
      case tcp_socket_operation_type::setopt_ip_tos:
      {
         if (0 > result) [[unlikely]]
         {
            log_system_error(std::source_location::current(), "[tcp_thread] failed to set IP_TOS socket option: ({}) - {}", -result);
            result = 0;
         }
         if (0 < tcpSocketOptions.tcpKeepCnt)
         {
            tcpSocketOperation.type = tcp_socket_operation_type::setopt_tcp_keepcnt;
            prep_sockopt_direct(tcpSocketOperation, IPPROTO_TCP, TCP_KEEPCNT, tcpSocketOptions.tcpKeepCnt);
            break;
         }
         else
         {
            assert(0 == tcpSocketOptions.tcpKeepCnt);
         }
      } [[fallthrough]];
      case tcp_socket_operation_type::setopt_tcp_keepcnt:
      {
         if (0 > result) [[unlikely]]
         {
            std::error_code const errorCode{-result, std::generic_category(),};
            log_system_error(std::source_location::current(), "[tcp_thread] failed to set TCP_KEEPCNT socket option: ({}) - {}", errorCode);
            handle_disconnect(tcpSocketOperation, errorCode);
            break;
         }
         if (0 < tcpSocketOptions.tcpKeepIdle)
         {
            tcpSocketOperation.type = tcp_socket_operation_type::setopt_tcp_keepidle;
            prep_sockopt_direct(tcpSocketOperation, IPPROTO_TCP, TCP_KEEPIDLE, tcpSocketOptions.tcpKeepIdle);
            break;
         }
         else
         {
            assert(0 == tcpSocketOptions.tcpKeepIdle);
         }
      } [[fallthrough]];
      case tcp_socket_operation_type::setopt_tcp_keepidle:
      {
         if (0 > result) [[unlikely]]
         {
            std::error_code const errorCode{-result, std::generic_category(),};
            log_system_error(std::source_location::current(), "[tcp_thread] failed to set TCP_KEEPIDLE socket option: ({}) - {}", errorCode);
            handle_disconnect(tcpSocketOperation, errorCode);
            break;
         }
         if (0 < tcpSocketOptions.tcpKeepIdle)
         {
            tcpSocketOperation.type = tcp_socket_operation_type::setopt_tcp_keepintvl;
            prep_sockopt_direct(tcpSocketOperation, IPPROTO_TCP, TCP_KEEPINTVL, tcpSocketOptions.tcpKeepIntvl);
            break;
         }
         else
         {
            assert(0 == tcpSocketOptions.tcpKeepIntvl);
         }
      } [[fallthrough]];
      case tcp_socket_operation_type::setopt_tcp_keepintvl:
      {
         if (0 > result) [[unlikely]]
         {
            std::error_code const errorCode{-result, std::generic_category(),};
            log_system_error(std::source_location::current(), "[tcp_thread] failed to set TCP_KEEPINTVL socket option: ({}) - {}", errorCode);
            handle_disconnect(tcpSocketOperation, errorCode);
            break;
         }
         if (1 == tcpSocketOptions.tcpNoDelay)
         {
            tcpSocketOperation.type = tcp_socket_operation_type::setopt_tcp_nodelay;
            prep_sockopt_direct(tcpSocketOperation, IPPROTO_TCP, TCP_NODELAY, tcpSocketOptions.tcpNoDelay);
            break;
         }
         else
         {
            assert(0 == tcpSocketOptions.tcpNoDelay);
         }
      } [[fallthrough]];
      case tcp_socket_operation_type::setopt_tcp_nodelay:
      {
         if (0 > result) [[unlikely]]
         {
            std::error_code const errorCode{-result, std::generic_category(),};
            log_system_error(std::source_location::current(), "[tcp_thread] failed to set TCP_NODELAY socket option: ({}) - {}", errorCode);
            handle_disconnect(tcpSocketOperation, errorCode);
            break;
         }
         if (0 < tcpSocketOptions.tcpUserTimeout)
         {
            tcpSocketOperation.type = tcp_socket_operation_type::setopt_tcp_syncnt;
            prep_sockopt_direct(tcpSocketOperation, IPPROTO_TCP, TCP_SYNCNT, m_tcpSynCnt);
            break;
         }
      } [[fallthrough]];
      case tcp_socket_operation_type::setopt_tcp_syncnt:
      {
         if (0 > result) [[unlikely]]
         {
            log_system_error(std::source_location::current(), "[tcp_thread] failed to set TCP_SYNCNT socket option: ({}) - {}", -result);
            result = 0;
         }
         if (1 == tcpSocketOptions.tcpUserTimeout)
         {
            tcpSocketOperation.type = tcp_socket_operation_type::setopt_tcp_user_timeout;
            prep_sockopt_direct(tcpSocketOperation, IPPROTO_TCP, TCP_USER_TIMEOUT, tcpSocketOptions.tcpUserTimeout);
            break;
         }
         else
         {
            assert(0 == tcpSocketOptions.tcpUserTimeout);
         }
      } [[fallthrough]];
      case tcp_socket_operation_type::setopt_tcp_user_timeout:
      {
         if (0 > result) [[unlikely]]
         {
            std::error_code const errorCode{-result, std::generic_category(),};
            log_system_error(std::source_location::current(), "[tcp_thread] failed to set TCP_USER_TIMEOUT socket option: ({}) - {}", errorCode);
            handle_disconnect(tcpSocketOperation, errorCode);
            break;
         }
         tcpSocketOperation.type = tcp_socket_operation_type::connect;
         auto &submissionQueueEntry = m_uringWorker->submission_entry(std::addressof(tcpSocketOperation));
         io_uring_prep_connect(
            std::addressof(submissionQueueEntry),
            tcpSocketOperation.descriptor->registeredTcpSocketIndex,
            std::addressof(tcpSocketOptions.address.ip),
            (AF_INET == tcpSocketOptions.address.addressFamily) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6)
         );
         submissionQueueEntry.flags |= IOSQE_FIXED_FILE;
         m_uringStopToken.increment_tasks_count();
      }
      break;

      case tcp_socket_operation_type::connect:
      {
         if (0 > result) [[unlikely]]
         {
            std::error_code const errorCode{-result, std::generic_category(),};
            log_system_error(std::source_location::current(), "[tcp_thread] failed to connect TCP socket: ({}) - {}", errorCode);
            handle_disconnect(tcpSocketOperation, errorCode);
            break;
         }
         std::destroy_at(std::addressof(tcpSocketOptions));
         tcpSocketOperation.type = tcp_socket_operation_type::recv;
         tcpSocketDescriptor.tcpSocketStatus = tcp_socket_status::ready;
         recv(tcpSocketOperation);
         send(*tcpSocketOperation.descriptor);
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

   void handle_disconnect_completion(tcp_socket_operation &tcpSocketOperation, int32_t const result, [[maybe_unused]] uint32_t const flags)
   {
      assert(0 == flags);
      if (0 > result) [[unlikely]]
      {
         log_system_error(std::source_location::current(), "[tcp_thread] failed to disconnect TCP socket: ({}) - {}", -result);
      }
      handle_disconnect(tcpSocketOperation, std::error_code{});
   }

   void handle_disconnect(tcp_socket_operation &tcpSocketOperation, std::error_code const errorCode)
   {
      assert(nullptr == tcpSocketOperation.next);
      assert(nullptr != tcpSocketOperation.descriptor);
      assert(tcp_socket_status::none != tcpSocketOperation.descriptor->tcpSocketStatus);
      assert(nullptr == tcpSocketOperation.descriptor->next);
      assert(tcp_socket_operation_type::none != tcpSocketOperation.type);
      auto &tcpSocketDescriptor = *tcpSocketOperation.descriptor;
      if (nullptr != tcpSocketDescriptor.tcpClient)
      {
         tcpSocketDescriptor.tcpClient->io_disconnected(errorCode);
         tcpSocketDescriptor.tcpClient = nullptr;
      }
      if (tcp_socket_operation_type::socket != tcpSocketOperation.type)
      {
         if (tcp_socket_operation_type::close == tcpSocketOperation.type)
         {
            assert(tcp_socket_status::disconnecting == tcpSocketDescriptor.tcpSocketStatus);
         }
         else
         {
            assert(tcp_socket_status::none != tcpSocketDescriptor.tcpSocketStatus);
            tcpSocketOperation.type = tcp_socket_operation_type::close;
            tcpSocketDescriptor.tcpSocketStatus = tcp_socket_status::disconnecting;
            io_uring_prep_close_direct(
               std::addressof(m_uringWorker->submission_entry(std::addressof(tcpSocketOperation))),
               tcpSocketDescriptor.registeredTcpSocketIndex
            );
            return;
         }
      }
      tcpSocketOperation.next = std::launder(m_tcpSocketOperations);
      tcpSocketOperation.descriptor = nullptr;
      tcpSocketOperation.bufferOffset = 0;
      tcpSocketOperation.type = tcp_socket_operation_type::none;
      m_tcpSocketOperations = std::launder(std::addressof(tcpSocketOperation));
      tcpSocketDescriptor.tcpSocketStatus = tcp_socket_status::none;
      tcpSocketDescriptor.disconnectOnCompletion = false;
      tcpSocketDescriptor.next = std::launder(m_tcpSocketDescriptors);
      m_tcpSocketDescriptors = std::launder(std::addressof(tcpSocketDescriptor));
   }

   void handle_ready_to_connect(tcp_client &tcpClient)
   {
      assert(nullptr == tcpClient.m_socketDescriptor);
      if (nullptr == m_tcpSocketDescriptors) [[unlikely]]
      {
         log_error(std::source_location::current(), "[tcp_client] too few socket descriptors provided, please increase capacity of socket descriptor list");
         unreachable();
      }
      if (nullptr == m_tcpSocketOperations) [[unlikely]]
      {
         log_error(std::source_location::current(), "[tcp_client] too few socket operations provided, it must be a bug");
         unreachable();
      }
      auto &tcpSocketDescriptor{*std::launder(m_tcpSocketDescriptors)};
      m_tcpSocketDescriptors = std::launder(tcpSocketDescriptor.next);
      tcpSocketDescriptor.next = nullptr;
      assert(tcp_socket_status::none == tcpSocketDescriptor.tcpSocketStatus);
      assert(false == tcpSocketDescriptor.disconnectOnCompletion);
      assert(nullptr == tcpSocketDescriptor.tcpClient);
      tcpClient.m_socketDescriptor = std::addressof(tcpSocketDescriptor);
      tcpSocketDescriptor.tcpSocketStatus = tcp_socket_status::connecting;
      tcpSocketDescriptor.tcpClient = std::addressof(tcpClient);
      auto config{tcpClient.io_ready_to_connect(),};
      auto &tcpSocketOperation{*std::launder(m_tcpSocketOperations)};
      assert(nullptr == tcpSocketOperation.descriptor);
      assert(0 == tcpSocketOperation.bufferOffset);
      assert(tcp_socket_operation_type::none == tcpSocketOperation.type);
      tcpSocketOperation.next = nullptr;
      tcpSocketOperation.descriptor = std::addressof(tcpSocketDescriptor);
      tcpSocketOperation.type = tcp_socket_operation_type::socket;
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
      io_uring_prep_socket_direct(
         std::addressof(m_uringWorker->submission_entry(std::addressof(tcpSocketOperation))),
         tcpSocketOptions.address.addressFamily,
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

   void handle_recv_completion(tcp_socket_operation &tcpSocketOperation, int32_t const result, [[maybe_unused]] uint32_t const flags)
   {
      (void)tcpSocketOperation;
      assert(0 == flags);
      if (0 > result) [[unlikely]]
      {

      }
   }

   void handle_received_data(tcp_client &tcpClient, size_t const bytesReceived)
   {
      assert(nullptr != tcpClient.m_socketDescriptor);
      auto &socketDescriptor{*tcpClient.m_socketDescriptor};
      (void)socketDescriptor;
      (void)bytesReceived;
   }

   void handle_send_completion(tcp_socket_operation &tcpSocketOperation, int32_t const result, [[maybe_unused]] uint32_t const flags)
   {
      (void)tcpSocketOperation;
      assert(0 == flags);
      if (0 > result) [[unlikely]]
      {

      }
   }

   void handle_thread_task(thread_task &task)
   {
      assert(task.routine);
      task.routine();
      task.completionPromise.set_value();
   }

   void recv(tcp_socket_operation &tcpSocketOperation)
   {
      assert(nullptr == tcpSocketOperation.next);
      assert(nullptr != tcpSocketOperation.descriptor);
      assert(
         false
         || (tcp_socket_status::ready == tcpSocketOperation.descriptor->tcpSocketStatus)
         || (tcp_socket_status::busy == tcpSocketOperation.descriptor->tcpSocketStatus)
      );
      assert(nullptr != tcpSocketOperation.descriptor->tcpClient);
      assert(nullptr == tcpSocketOperation.descriptor->next);
      assert(tcp_socket_operation_type::recv == tcpSocketOperation.type);
      auto &socketDescriptor{*tcpSocketOperation.descriptor,};
      auto &submissionQueueEntry{m_uringWorker->submission_entry(std::addressof(tcpSocketOperation)),};
      io_uring_prep_recv(
         std::addressof(submissionQueueEntry),
         socketDescriptor.registeredTcpSocketIndex,
         std::addressof(tcpSocketOperation.bufferBytes[0]) + tcpSocketOperation.bufferOffset,
         m_uringWorker->registered_buffer_capacity(tcpSocketOperation) - tcpSocketOperation.bufferOffset,
         0
      );
      submissionQueueEntry.flags |= IOSQE_FIXED_FILE;
      submissionQueueEntry.ioprio |= IORING_RECVSEND_FIXED_BUF;
      submissionQueueEntry.buf_index = tcpSocketOperation.bufferIndex;
      m_uringStopToken.increment_tasks_count();
   }

   void send(tcp_socket_descriptor &tcpSocketDescriptor)
   {
      auto &tcpSocketOperation{*m_tcpSocketOperations};
      assert(nullptr == tcpSocketOperation.descriptor);
      assert(0 == tcpSocketOperation.bufferOffset);
      assert(tcp_socket_operation_type::none == tcpSocketOperation.type);
      size_t bytesWritten{static_cast<size_t>(-1),};
      if (
         auto const errorCode
         {
            tcpSocketDescriptor.tcpClient->io_data_to_send(
               data_chunk
               {
                  .bytes = std::addressof(tcpSocketOperation.bufferBytes[0]),
                  .bytesLength = m_uringWorker->registered_buffer_capacity(tcpSocketOperation),
               },
               bytesWritten
            ),
         };
         true == bool{errorCode,}
      ) [[unlikely]]
      {
         handle_disconnect(tcpSocketOperation, errorCode);
         return;
      }
      assert(static_cast<size_t>(-1) != bytesWritten);
      if (0 == bytesWritten)
      {
         return;
      }
      m_tcpSocketOperations = std::launder(tcpSocketOperation.next);
      tcpSocketOperation.next = nullptr;
      tcpSocketOperation.descriptor = std::addressof(tcpSocketDescriptor);
      tcpSocketOperation.type = tcp_socket_operation_type::send;
      auto &submissionQueueEntry{m_uringWorker->submission_entry(std::addressof(tcpSocketOperation)),};
      io_uring_prep_send_zc_fixed(
         std::addressof(submissionQueueEntry),
         tcpSocketDescriptor.registeredTcpSocketIndex,
         std::addressof(tcpSocketOperation.bufferBytes[0]),
         bytesWritten,
         0,
         0,
         tcpSocketOperation.bufferIndex
      );
      submissionQueueEntry.flags |= IOSQE_FIXED_FILE;
   }
};

}
