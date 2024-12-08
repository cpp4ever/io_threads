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
#include "common/utility.hpp" ///< for io_threads::unreachable
#include "linux/file_descriptor.hpp" ///< for io_threads::file_descriptor
#include "linux/tcp_socket_descriptor.hpp" ///< for io_threads::tcp_socket_descriptor
#include "linux/tcp_socket_operation.hpp" ///< for io_threads::tcp_socket_operation
#include "linux/uring_listener.hpp" ///< for io_threads::uring_listener

#include <errno.h> ///< for errno
/// for
///   io_uring,
///   io_uring_cq_advance,
///   io_uring_cqe,
///   io_uring_cqe_get_data,
///   io_uring_ring_dontfork,
///   io_uring_get_sqe,
///   io_uring_for_each_cqe,
///   io_uring_queue_exit,
///   io_uring_queue_init,
///   io_uring_register_files,
///   io_uring_sqe,
///   io_uring_sqe_set_data,
///   io_uring_submit_and_wait_timeout,
///   io_uring_unregister_files,
///   IORING_SETUP_SINGLE_ISSUER
#include <liburing.h>
#include <signal.h> ///< for sigfillset, sigset_t
#include <sys/uio.h> ///< for iovec

#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <cstddef> ///< for size_t
#include <cstdint> ///< for int32_t, intptr_t, uint32_t
#include <memory> ///< for std::addressof, std::make_unique, std::unique_ptr
#include <new> ///< for std::align_val_t
#include <source_location> ///< for std::source_location
#include <vector> ///< for std::vector

namespace io_threads
{

class uring_worker final
{
public:
   uring_worker() = delete;
   uring_worker(uring_worker &&) = delete;
   uring_worker(uring_worker const &) = delete;

   [[nodiscard]] explicit uring_worker(size_t const capacityOfRingQueue)
   {
      assert(0 < capacityOfRingQueue);
      assert(nullptr != m_ring);
      if (
         auto const returnCode{io_uring_queue_init(capacityOfRingQueue, m_ring.get(), IORING_SETUP_SINGLE_ISSUER),};
         0 > returnCode
      ) [[unlikely]]
      {
         log_system_error(std::source_location::current(), "[io_uring] failed to initialize the ring: ({}) - {}", -returnCode);
         unreachable();
      }
      if (auto const returnCode{io_uring_ring_dontfork(m_ring.get()),}; 0 > returnCode) [[unlikely]]
      {
         log_system_error(std::source_location::current(), "[io_uring] failed to disable inheriting of the ring mappings: ({}) - {}", -returnCode);
      }
      if (-1 == sigfillset(m_sigmask.get())) [[unlikely]]
      {
         log_system_error(std::source_location::current(), "[io_uring] failed to initialize sigmask: ({}) - {}", errno);
         unreachable();
      }
   }

   ~uring_worker()
   {
      assert(nullptr != m_ring);
      io_uring_queue_exit(m_ring.get());
   }

   uring_worker &operator = (uring_worker &&) = delete;
   uring_worker &operator = (uring_worker const &) = delete;

   [[nodiscard]] file_descriptor *register_file_descriptors(uint32_t const capacityOfFileDescriptorList)
   {
      assert(0 < capacityOfFileDescriptorList);
      assert(nullptr != m_ring);
      assert(nullptr == m_registeredDescriptorsMemoryPool);
      assert(true == m_registeredDescriptors.empty());
      m_registeredDescriptors.resize(capacityOfFileDescriptorList, -1);
      if (
         auto const returnCode{io_uring_register_files(m_ring.get(), m_registeredDescriptors.data(), static_cast<uint32_t>(m_registeredDescriptors.size())),};
         0 > returnCode
      ) [[unlikely]]
      {
         log_system_error(std::source_location::current(), "[io_uring] failed to register files: ({}) - {}", -returnCode);
         unreachable();
      }
      m_registeredDescriptorsMemoryPool = std::make_unique<memory_pool>(
         capacityOfFileDescriptorList,
         std::align_val_t{alignof(file_descriptor),},
         sizeof(file_descriptor)
      );
      file_descriptor *fileDescriptors{nullptr,};
      for (
         uint32_t registeredFileIndex{static_cast<uint32_t>(capacityOfFileDescriptorList),};
         0 < registeredFileIndex;
         --registeredFileIndex
      )
      {
         fileDescriptors = std::addressof(
            m_registeredDescriptorsMemoryPool->pop_object<file_descriptor>(
               file_descriptor
               {
                  .registeredFileIndex = registeredFileIndex - 1,
                  .next = fileDescriptors,
               }
            )
         );
      }
      return fileDescriptors;
   }

   [[nodiscard]] tcp_socket_descriptor *register_tcp_socket_descriptors(uint32_t const capacityOfTcpSocketDescriptorList)
   {
      assert(0 < capacityOfTcpSocketDescriptorList);
      assert(nullptr != m_ring);
      assert(nullptr == m_registeredDescriptorsMemoryPool);
      assert(true == m_registeredDescriptors.empty());
      m_registeredDescriptors.resize(capacityOfTcpSocketDescriptorList, -1);
      if (
         auto const returnCode{io_uring_register_files(m_ring.get(), m_registeredDescriptors.data(), static_cast<uint32_t>(m_registeredDescriptors.size())),};
         0 > returnCode
      ) [[unlikely]]
      {
         log_system_error(std::source_location::current(), "[io_uring] failed to register TCP sockets: ({}) - {}", -returnCode);
         unreachable();
      }
      m_registeredDescriptorsMemoryPool = std::make_unique<memory_pool>(
         capacityOfTcpSocketDescriptorList,
         std::align_val_t{alignof(tcp_socket_descriptor),},
         sizeof(tcp_socket_descriptor)
      );
      tcp_socket_descriptor *tcpSocketDescriptors{nullptr,};
      for (
         uint32_t registeredTcpSocketIndex{static_cast<uint32_t>(capacityOfTcpSocketDescriptorList),};
         0 < registeredTcpSocketIndex;
         --registeredTcpSocketIndex
      )
      {
         tcpSocketDescriptors = std::addressof(
            m_registeredDescriptorsMemoryPool->pop_object<tcp_socket_descriptor>(
               tcp_socket_descriptor
               {
                  .registeredTcpSocketIndex = registeredTcpSocketIndex - 1,
                  .next = tcpSocketDescriptors,
               }
            )
         );
      }
      return tcpSocketDescriptors;
   }

   [[nodiscard]] tcp_socket_operation *register_tcp_socket_operations(
      uint32_t const capacityOfTcpSocketOperationList,
      size_t const capacityOfRegisteredBuffer
   )
   {
      assert(0 < capacityOfTcpSocketOperationList);
      assert(0 < capacityOfRegisteredBuffer);
      assert(nullptr != m_ring);
      assert(nullptr == m_registeredBuffersMemoryPool);
      assert(true == m_registeredBuffers.empty());
      m_registeredBuffersMemoryPool = std::make_unique<memory_pool>(
         capacityOfTcpSocketOperationList,
         std::align_val_t{alignof(tcp_socket_operation)},
         tcp_socket_operation::total_size(capacityOfRegisteredBuffer)
      );
      m_registeredBuffers.reserve(capacityOfTcpSocketOperationList);
      tcp_socket_operation *tcpSocketOperations{nullptr,};
      for (auto registeredBufferIndex{static_cast<uint32_t>(capacityOfTcpSocketOperationList),}; 0 < registeredBufferIndex; --registeredBufferIndex)
      {
         tcpSocketOperations = std::addressof(
            m_registeredBuffersMemoryPool->pop_object<tcp_socket_operation>(
               tcp_socket_operation
               {
                  .next = tcpSocketOperations,
                  .bufferIndex = registeredBufferIndex - 1,
               }
            )
         );
         m_registeredBuffers.push_back(
            iovec
            {
               .iov_base = std::addressof(tcpSocketOperations->bufferBytes),
               .iov_len = capacityOfRegisteredBuffer,
            }
         );
      }
      if (
         auto const returnCode{io_uring_register_buffers(m_ring.get(), m_registeredBuffers.data(), m_registeredBuffers.size()),};
         0 > returnCode
      ) [[unlikely]]
      {
         log_system_error(std::source_location::current(), "[io_uring] failed to register TCP socket operations: ({}) - {}", -returnCode);
         unreachable();
      }
      return tcpSocketOperations;
   }

   [[nodiscard]] io_uring_sqe &submission_entry(void *userdata)
   {
      assert(nullptr != userdata);
      assert(nullptr != m_ring);
      auto *submissionQueueEntry{io_uring_get_sqe(m_ring.get()),};
      if (nullptr == submissionQueueEntry) [[unlikely]]
      {
         log_error(std::source_location::current(), "[io_uring] failed to get submission queue entry");
         unreachable();
      }
      io_uring_sqe_set_data(submissionQueueEntry, userdata);
      return *submissionQueueEntry;
   }

   void submit_and_wait(uring_listener &uringListener)
   {
      assert(nullptr != m_ring);
      io_uring_cqe *completionQueueEntry{nullptr,};
      if (
         auto const returnCode{io_uring_submit_and_wait_timeout(m_ring.get(), std::addressof(completionQueueEntry), 1, nullptr, m_sigmask.get()),};
         0 > returnCode
      ) [[unlikely]]
      {
         log_system_error(std::source_location::current(), "[io_uring] failed to submit prepared tasks: ({}) - {}", -returnCode);
         unreachable();
      }
      uint32_t completionQueueHead;
      uint32_t numberOfCompletionQueueEntriesRemoved{0,};
      io_uring_for_each_cqe(m_ring.get(), completionQueueHead, completionQueueEntry)
      {
         auto *userdata{io_uring_cqe_get_data(completionQueueEntry),};
         assert(nullptr != userdata);
         uringListener.handle_completion(std::bit_cast<intptr_t>(userdata), completionQueueEntry->res, completionQueueEntry->flags);
         ++numberOfCompletionQueueEntriesRemoved;
      }
      io_uring_cq_advance(m_ring.get(), numberOfCompletionQueueEntriesRemoved);
   }

   void unregister_file_descriptors(file_descriptor *fileDescriptors)
   {
      assert(nullptr != fileDescriptors);
      assert(nullptr != m_ring);
      assert(nullptr != m_registeredDescriptorsMemoryPool);
      assert((std::align_val_t{alignof(file_descriptor),}) == m_registeredDescriptorsMemoryPool->memory_alignment());
      assert(sizeof(file_descriptor) == m_registeredDescriptorsMemoryPool->memory_size());
      assert(false == m_registeredDescriptors.empty());
      if (auto const returnCode{io_uring_unregister_files(m_ring.get()),}; 0 > returnCode)
      {
         log_system_error(std::source_location::current(), "[io_uring] failed to unregister files: ({}) - {}", -returnCode);
      }
      while (nullptr != fileDescriptors)
      {
         auto *fileDescriptor{std::launder(fileDescriptors),};
         assert(file_status::none == fileDescriptor->fileStatus);
         assert(false == fileDescriptor->closeOnCompletion);
         assert(nullptr == fileDescriptor->fileWriter);
         fileDescriptors = fileDescriptor->next;
         m_registeredDescriptorsMemoryPool->push_object(*fileDescriptor);
      }
      m_registeredDescriptors.clear();
      m_registeredDescriptorsMemoryPool.reset();
   }

   void unregister_tcp_socket_descriptors(tcp_socket_descriptor *tcpSocketDescriptors)
   {
      assert(nullptr != tcpSocketDescriptors);
      assert(nullptr != m_ring);
      assert(nullptr != m_registeredDescriptorsMemoryPool);
      assert((std::align_val_t{alignof(tcp_socket_descriptor),}) == m_registeredDescriptorsMemoryPool->memory_alignment());
      assert(sizeof(tcp_socket_descriptor) == m_registeredDescriptorsMemoryPool->memory_size());
      assert(false == m_registeredDescriptors.empty());
      if (auto const returnCode{io_uring_unregister_files(m_ring.get()),}; 0 > returnCode)
      {
         log_system_error(std::source_location::current(), "[io_uring] failed to unregister TCP sockets: ({}) - {}", -returnCode);
      }
      while (nullptr != tcpSocketDescriptors)
      {
         auto *tcpSocketDescriptor{std::launder(tcpSocketDescriptors),};
         assert(tcp_socket_status::none == tcpSocketDescriptor->tcpSocketStatus);
         assert(false == tcpSocketDescriptor->disconnectOnCompletion);
         assert(nullptr == tcpSocketDescriptor->tcpClient);
         tcpSocketDescriptors = tcpSocketDescriptor->next;
         m_registeredDescriptorsMemoryPool->push_object(*tcpSocketDescriptor);
      }
      m_registeredDescriptors.clear();
      m_registeredDescriptorsMemoryPool.reset();
   }

   void unregister_tcp_socket_operations(tcp_socket_operation *tcpSocketOperations)
   {
      assert(nullptr != tcpSocketOperations);
      assert(nullptr != m_ring);
      assert(nullptr != m_registeredBuffersMemoryPool);
      assert((std::align_val_t{alignof(tcp_socket_operation),}) == m_registeredBuffersMemoryPool->memory_alignment());
      assert(sizeof(tcp_socket_operation) <= m_registeredBuffersMemoryPool->memory_size());
      assert(false == m_registeredBuffers.empty());
      if (auto const returnCode{io_uring_unregister_buffers(m_ring.get()),}; 0 > returnCode)
      {
         log_system_error(std::source_location::current(), "[io_uring] failed to unregister TCP socket operations: ({}) - {}", -returnCode);
         unreachable();
      }
      while (nullptr != tcpSocketOperations)
      {
         auto *tcpSocketOperation{std::launder(tcpSocketOperations),};
         assert(nullptr == tcpSocketOperation->descriptor);
         assert(0 == tcpSocketOperation->bufferOffset);
         assert(tcp_socket_operation_type::none == tcpSocketOperation->type);
         tcpSocketOperations = tcpSocketOperation->next;
         m_registeredBuffersMemoryPool->push_object(*tcpSocketOperation);
      }
      m_registeredBuffers.clear();
      m_registeredBuffersMemoryPool.reset();
   }

private:
   std::unique_ptr<io_uring> m_ring{std::make_unique<io_uring>(),};
   std::unique_ptr<sigset_t> m_sigmask{std::make_unique<sigset_t>(),};
   std::unique_ptr<memory_pool> m_registeredBuffersMemoryPool{nullptr,};
   std::vector<iovec> m_registeredBuffers{};
   std::unique_ptr<memory_pool> m_registeredDescriptorsMemoryPool{nullptr,};
   std::vector<int32_t> m_registeredDescriptors{};
};

}
