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

#if (defined(__linux__))
#include "common/logger.hpp" ///< for io_threads::log_error, io_threads::log_system_error
#include "common/memory_pool.hpp" ///< for io_threads::memory_pool
#include "common/utility.hpp" ///< for io_threads::unreachable
#include "linux/tcp_client_uring.hpp" ///< for io_threads::tcp_client_uring
#include "linux/tcp_socket_descriptor.hpp" ///< for io_threads::tcp_socket_descriptor
#include "linux/tcp_socket_operation.hpp" ///< for io_threads::tcp_socket_operation

#include <errno.h> ///< for errno
#include <liburing.h>
#include <linux/time_types.h> ///< for __kernel_timespec
#include <netinet/in.h> ///< for IPPROTO_TCP
#include <sched.h> ///< for CPU_SET, cpu_set_t, CPU_ZERO
#include <signal.h> ///< for sigfillset, sigset_t
#include <sys/eventfd.h> ///< for EFD_NONBLOCK, eventfd, eventfd_t, eventfd_write
#include <sys/socket.h> ///< for sa_family_t, SOCK_NONBLOCK, SOCK_STREAM
#include <sys/uio.h> ///< for iovec

#include <cassert> ///< for assert
#include <cstddef> ///< for size_t
#include <cstdint> ///< fro uint16_t, uint32_t
#include <memory> ///< for std::addressof, std::make_unique, std::unique_ptr
#include <new> ///< for std::align_val_t, std::launder
#include <optional> ///< for std::optional
#include <source_location> ///< for std::source_location
#include <stop_token> ///< for std::stop_token
#include <vector> ///< for std::vector

namespace io_threads
{

class tcp_client_uring_impl final : public tcp_client_uring
{
public:
   tcp_client_uring_impl() = delete;
   tcp_client_uring_impl(tcp_client_uring_impl &&) = delete;
   tcp_client_uring_impl(tcp_client_uring_impl const &) = delete;

   [[nodiscard]] tcp_client_uring_impl(std::optional<uint16_t> const ioCpuAffinity, size_t const ioRingQueueCapacity)
   {
      assert(0 < ioRingQueueCapacity);
      assert(nullptr != m_ring);
      if (
         auto const returnCode{io_uring_queue_init(ioRingQueueCapacity, m_ring.get(), IORING_SETUP_SINGLE_ISSUER),};
         0 > returnCode
      ) [[unlikely]]
      {
         log_system_error("[tcp_client] failed to initialize the ring: ({}) - {}", -returnCode);
         unreachable();
      }
      if (auto const returnCode{io_uring_register_ring_fd(m_ring.get()),}; 0 > returnCode) [[unlikely]]
      {
         log_system_error("[tcp_client] failed to register ring descriptor: ({}) - {}", -returnCode);
      }
      if (true == ioCpuAffinity.has_value())
      {
         cpu_set_t iowqAffinityMask;
         CPU_ZERO(std::addressof(iowqAffinityMask));
         CPU_SET(ioCpuAffinity.value(), std::addressof(iowqAffinityMask));
         if (auto const returnCode{io_uring_register_iowq_aff(m_ring.get(), sizeof(iowqAffinityMask), std::addressof(iowqAffinityMask)),}; 0 > returnCode) [[unlikely]]
         {
            log_system_error("[tcp_client] failed to register IO workers affinity mask: ({}) - {}", -returnCode);
         }
      }
      std::array<uint32_t, 2> iowqMaxWorkers = {static_cast<uint32_t>(ioRingQueueCapacity), static_cast<uint32_t>(ioRingQueueCapacity),};
      if (auto const returnCode{io_uring_register_iowq_max_workers(m_ring.get(), iowqMaxWorkers.data()),}; 0 > returnCode) [[unlikely]]
      {
         log_system_error("[tcp_client] failed to register IO workers limits: ({}) - {}", -returnCode);
      }
      if (auto const returnCode{io_uring_ring_dontfork(m_ring.get()),}; 0 > returnCode) [[unlikely]]
      {
         log_system_error("[tcp_client] failed to disable inheriting of the ring mappings: ({}) - {}", -returnCode);
      }
      if (-1 == sigfillset(m_sigmask.get())) [[unlikely]]
      {
         log_system_error("[tcp_client] failed to initialize sigmask: ({}) - {}", errno);
         unreachable();
      }
      if (-1 == (m_eventfd = eventfd(0, EFD_NONBLOCK))) [[unlikely]]
      {
         log_system_error("[tcp_client] failed to create eventfd: ({}) - {}", errno);
         unreachable();
      }
   }

   ~tcp_client_uring_impl() override
   {
      assert(nullptr != m_ring);
      assert(0 == m_tasksCount);
      assert(-1 != m_eventfd);
      if (-1 == close(m_eventfd)) [[unlikely]]
      {
         log_system_error("[tcp_client] failed to destroy eventfd: ({}) - {}", errno);
      }
      if (auto const returnCode{io_uring_unregister_iowq_aff(m_ring.get()),}; 0 > returnCode) [[unlikely]]
      {
         log_system_error("[tcp_client] failed to unregister IO workers affinity mask: ({}) - {}", -returnCode);
      }
      if (auto const returnCode{io_uring_unregister_ring_fd(m_ring.get()),}; 0 > returnCode) [[unlikely]]
      {
         log_system_error("[tcp_client] failed to unregister ring descriptor: ({}) - {}", -returnCode);
      }
      io_uring_queue_exit(m_ring.get());
   }

   tcp_client_uring_impl &operator = (tcp_client_uring_impl &&) = delete;
   tcp_client_uring_impl &operator = (tcp_client_uring_impl const &) = delete;

   void prep_close(tcp_socket_operation &tcpSocketOperation) override
   {
      assert(nullptr != tcpSocketOperation.descriptor);
      io_uring_prep_close_direct(
         std::addressof(submission_queue_entry(std::addressof(tcpSocketOperation))),
         tcpSocketOperation.descriptor->registeredSocketIndex
      );
   }

   void prep_connect(tcp_socket_operation &tcpSocketOperation, sockaddr const &socketAddress) override
   {
      assert(nullptr != tcpSocketOperation.descriptor);
      assert((AF_INET == socketAddress.sa_family) || (AF_INET6 == socketAddress.sa_family));
      auto &submissionQueueEntry = submission_queue_entry(std::addressof(tcpSocketOperation));
      io_uring_prep_connect(
         std::addressof(submissionQueueEntry),
         tcpSocketOperation.descriptor->registeredSocketIndex,
         std::addressof(socketAddress),
         (AF_INET == socketAddress.sa_family) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6)
      );
      submissionQueueEntry.flags |= IOSQE_FIXED_FILE;
   }

   void prep_recv(tcp_socket_operation &tcpSocketOperation) override
   {
      assert(nullptr != tcpSocketOperation.descriptor);
      assert(nullptr != m_tcpSocketOperationsMemoryPool);
      assert(registered_buffer_capacity(tcpSocketOperation) > tcpSocketOperation.bufferOffset);
      auto &submissionQueueEntry{submission_queue_entry(std::addressof(tcpSocketOperation)),};
      io_uring_prep_read_fixed(
         std::addressof(submissionQueueEntry),
         tcpSocketOperation.descriptor->registeredSocketIndex,
         std::addressof(tcpSocketOperation.bufferBytes[tcpSocketOperation.bufferOffset]),
         registered_buffer_capacity(tcpSocketOperation) - tcpSocketOperation.bufferOffset,
         0,
         tcpSocketOperation.bufferIndex
      );
      submissionQueueEntry.flags |= IOSQE_FIXED_FILE;
   }

   void prep_send(tcp_socket_operation &tcpSocketOperation, size_t const bytesLength) override
   {
      assert(nullptr != tcpSocketOperation.descriptor);
      assert(nullptr != m_tcpSocketOperationsMemoryPool);
      assert((bytesLength + tcpSocketOperation.bufferOffset) <= registered_buffer_capacity(tcpSocketOperation));
      auto &submissionQueueEntry{submission_queue_entry(std::addressof(tcpSocketOperation)),};
      io_uring_prep_send_zc_fixed(
         std::addressof(submissionQueueEntry),
         tcpSocketOperation.descriptor->registeredSocketIndex,
         std::addressof(tcpSocketOperation.bufferBytes[tcpSocketOperation.bufferOffset]),
         bytesLength,
         MSG_DONTWAIT | MSG_NOSIGNAL,
         0,
         tcpSocketOperation.bufferIndex
      );
      submissionQueueEntry.flags |= IOSQE_FIXED_FILE;
   }

#if ((2 < IO_URING_VERSION_MAJOR) || ((2 == IO_URING_VERSION_MAJOR) && (6 <= IO_URING_VERSION_MINOR)))
   void prep_setsockopt(
      tcp_socket_operation &tcpSocketOperation,
      int sockoptLevel,
      int sockoptName,
      void *sockoptValue,
      int sockoptValueSize
   ) override
   {
      assert(nullptr != tcpSocketOperation.descriptor);
      assert(nullptr != sockoptValue);
      assert(0 < sockoptValueSize);
      auto &submissionQueueEntry{submission_queue_entry(std::addressof(tcpSocketOperation)),};
      io_uring_prep_cmd_sock(
         std::addressof(submissionQueueEntry),
         SOCKET_URING_OP_SETSOCKOPT,
         tcpSocketOperation.descriptor->registeredSocketIndex,
         sockoptLevel,
         sockoptName,
         sockoptValue,
         sockoptValueSize
      );
      submissionQueueEntry.flags |= IOSQE_FIXED_FILE;
   }

   void prep_setsockopt(
      tcp_socket_operation &tcpSocketOperation,
      int sockoptLevel,
      int sockoptName,
      int sockoptValue
   ) override
   {
      prep_setsockopt(tcpSocketOperation, sockoptLevel, sockoptName, std::addressof(sockoptValue), sizeof(sockoptValue));
   }
#endif

   void prep_shutdown(tcp_socket_operation &tcpSocketOperation, int32_t const how) override
   {
      assert(nullptr != tcpSocketOperation.descriptor);
      auto &submissionQueueEntry{submission_queue_entry(std::addressof(tcpSocketOperation)),};
      io_uring_prep_shutdown(std::addressof(submissionQueueEntry), tcpSocketOperation.descriptor->registeredSocketIndex, how);
      submissionQueueEntry.flags |= IOSQE_FIXED_FILE;
   }

   void prep_socket(tcp_socket_operation &tcpSocketOperation, sa_family_t const addressFamily) override
   {
      assert(nullptr != tcpSocketOperation.descriptor);
      assert((AF_INET == addressFamily) || (AF_INET6 == addressFamily));
#if ((2 < IO_URING_VERSION_MAJOR) || ((2 == IO_URING_VERSION_MAJOR) && (6 <= IO_URING_VERSION_MINOR)))
      io_uring_prep_socket_direct(
         std::addressof(submission_queue_entry(std::addressof(tcpSocketOperation))),
         addressFamily,
         SOCK_STREAM | SOCK_NONBLOCK,
         IPPROTO_TCP,
         tcpSocketOperation.descriptor->registeredSocketIndex,
         0
      );
#else
      io_uring_prep_socket(
         std::addressof(submission_queue_entry(std::addressof(tcpSocketOperation))),
         addressFamily,
         SOCK_STREAM | SOCK_NONBLOCK,
         IPPROTO_TCP,
         0
      );
#endif
   }

   void register_tcp_socket(tcp_socket_descriptor &tcpSocketDescriptor, int32_t const tcpSocket) override
   {
      if (
         auto const returnCode{io_uring_register_files_update(m_ring.get(), tcpSocketDescriptor.registeredSocketIndex, std::addressof(tcpSocket), 1),};
         0 > returnCode
      ) [[unlikely]]
      {
         log_system_error("[tcp_client] failed to register TCP socket: ({}) - {}", -returnCode);
         unreachable();
      }
   }

   [[nodiscard]] tcp_socket_descriptor *register_tcp_socket_descriptors(uint32_t const socketListCapacity) override
   {
      assert(0 < socketListCapacity);
      assert(nullptr != m_ring);
      assert(nullptr == m_tcpSocketDescriptorsMemoryPool);
      assert(true == m_registeredSockets.empty());
      m_registeredSockets.resize(socketListCapacity + 1, -1);
      if (
         auto const returnCode{io_uring_register_files(m_ring.get(), m_registeredSockets.data(), static_cast<uint32_t>(m_registeredSockets.size())),};
         0 > returnCode
      ) [[unlikely]]
      {
         log_system_error("[tcp_client] failed to register TCP sockets: ({}) - {}", -returnCode);
         unreachable();
      }
      m_tcpSocketDescriptorsMemoryPool = std::make_unique<memory_pool>(
         socketListCapacity,
         std::align_val_t{alignof(tcp_socket_descriptor),},
         sizeof(tcp_socket_descriptor)
      );
      tcp_socket_descriptor *tcpSocketDescriptors{nullptr,};
      for (auto registeredTcpSocketIndex{socketListCapacity,}; 0 < registeredTcpSocketIndex; --registeredTcpSocketIndex)
      {
         tcpSocketDescriptors = std::addressof(
            m_tcpSocketDescriptorsMemoryPool->pop_object<tcp_socket_descriptor>(
               tcp_socket_descriptor{.registeredSocketIndex = registeredTcpSocketIndex, .next = std::launder(tcpSocketDescriptors),}
            )
         );
      }
      register_eventfd();
      prep_read_eventfd();
      return tcpSocketDescriptors;
   }

   [[nodiscard]] tcp_socket_operation *register_tcp_socket_operations(
      uint32_t const socketOperationListCapacity,
      size_t const registeredBufferCapacity
   ) override
   {
      assert(0 < socketOperationListCapacity);
      assert(sizeof(tcp_socket_operation) <= registeredBufferCapacity);
      assert(nullptr != m_ring);
      assert(nullptr == m_tcpSocketOperationsMemoryPool);
      assert(true == m_registeredBuffers.empty());
      m_tcpSocketOperationsMemoryPool = std::make_unique<memory_pool>(
         socketOperationListCapacity,
         std::align_val_t{alignof(tcp_socket_operation),},
         registeredBufferCapacity
      );
      m_registeredBuffers.reserve(socketOperationListCapacity + 1);
      tcp_socket_operation *tcpSocketOperations{nullptr,};
      for (auto registeredBufferIndex{socketOperationListCapacity,}; 0 < registeredBufferIndex; --registeredBufferIndex)
      {
         tcpSocketOperations = std::addressof(
            m_tcpSocketOperationsMemoryPool->pop_object<tcp_socket_operation>(
               tcp_socket_operation{.next = std::launder(tcpSocketOperations), .bufferIndex = registeredBufferIndex,}
            )
         );
      }
      m_registeredBuffers.push_back(iovec{.iov_base = std::addressof(m_eventfdValue), .iov_len = sizeof(m_eventfdValue),});
      for (auto *tcpSocketOperation = tcpSocketOperations; nullptr != tcpSocketOperation; tcpSocketOperation = tcpSocketOperation->next)
      {
         m_registeredBuffers.push_back(
            iovec{.iov_base = tcpSocketOperation->bufferBytes, .iov_len = registered_buffer_capacity(*tcpSocketOperation),}
         );
      }
      if (
         auto const returnCode{io_uring_register_buffers(m_ring.get(), m_registeredBuffers.data(), m_registeredBuffers.size()),};
         0 > returnCode
      ) [[unlikely]]
      {
         log_system_error("[tcp_client] failed to register TCP socket operations: ({}) - {}", -returnCode);
         unreachable();
      }
      return tcpSocketOperations;
   }

   [[nodiscard]] size_t registered_buffer_capacity(tcp_socket_operation &) const override
   {
      assert(nullptr != m_tcpSocketOperationsMemoryPool);
      return tcp_socket_operation::buffer_bytes_capacity(m_tcpSocketOperationsMemoryPool->memory_chunk_size());
   }

   void unregister_tcp_socket_descriptors(tcp_socket_descriptor *tcpSocketDescriptors) override
   {
      assert(nullptr != tcpSocketDescriptors);
      assert(nullptr != m_ring);
      assert(nullptr != m_tcpSocketDescriptorsMemoryPool);
      assert(false == m_registeredSockets.empty());
      if (auto const returnCode{io_uring_unregister_files(m_ring.get()),}; 0 > returnCode) [[unlikely]]
      {
         log_system_error("[tcp_client] failed to unregister TCP sockets: ({}) - {}", -returnCode);
      }
      while (nullptr != tcpSocketDescriptors)
      {
         auto *tcpSocketDescriptor{std::launder(tcpSocketDescriptors),};
         assert(tcp_socket_status::none == tcpSocketDescriptor->tcpSocketStatus);
         assert(0 == tcpSocketDescriptor->refsCount);
         assert(nullptr == tcpSocketDescriptor->tcpClient);
         assert(false == (bool{tcpSocketDescriptor->disconnectReason,}));
         tcpSocketDescriptors = std::launder(tcpSocketDescriptor->next);
         tcpSocketDescriptor->next = nullptr;
         m_tcpSocketDescriptorsMemoryPool->push_object(*tcpSocketDescriptor);
      }
      m_registeredSockets.clear();
      m_tcpSocketDescriptorsMemoryPool.reset();
   }

   void unregister_tcp_socket_operations(tcp_socket_operation *tcpSocketOperations) override
   {
      assert(nullptr != tcpSocketOperations);
      assert(nullptr != m_ring);
      assert(nullptr != m_tcpSocketOperationsMemoryPool);
      assert(false == m_registeredBuffers.empty());
      if (auto const returnCode{io_uring_unregister_buffers(m_ring.get()),}; 0 > returnCode) [[unlikely]]
      {
         log_system_error("[tcp_client] failed to unregister TCP socket operations: ({}) - {}", -returnCode);
         unreachable();
      }
      while (nullptr != tcpSocketOperations)
      {
         auto *tcpSocketOperation{std::launder(tcpSocketOperations),};
         assert(nullptr == tcpSocketOperation->descriptor);
         assert(0 == tcpSocketOperation->bufferOffset);
         assert(tcp_socket_operation_type::none == tcpSocketOperation->type);
         tcpSocketOperations = std::launder(tcpSocketOperation->next);
         tcpSocketOperation->next = nullptr;
         m_tcpSocketOperationsMemoryPool->push_object(*tcpSocketOperation);
      }
      m_registeredBuffers.clear();
      m_tcpSocketOperationsMemoryPool.reset();
   }

   [[nodiscard]] intptr_t poll(uring_listener &uringListener, __kernel_timespec *timeout) final
   {
      io_uring_cqe *completionQueueEntry{nullptr,};
      if (
         auto const returnCode{io_uring_submit_and_wait_timeout(m_ring.get(), std::addressof(completionQueueEntry), 1, timeout, m_sigmask.get()),};
         (0 > returnCode) && (ETIME != -returnCode)
      ) [[unlikely]]
      {
         log_system_error("[tcp_client] failed to submit prepared tasks: ({}) - {}", -returnCode);
         unreachable();
      }
      uint32_t completionQueueHead;
      uint32_t numberOfCompletionQueueEntriesRemoved{0,};
      io_uring_for_each_cqe(m_ring.get(), completionQueueHead, completionQueueEntry)
      {
         assert(0 < m_tasksCount);
         if (IORING_CQE_F_MORE != (IORING_CQE_F_MORE & completionQueueEntry->flags))
         {
            --m_tasksCount;
         }
         auto *userdata{io_uring_cqe_get_data(completionQueueEntry),};
         assert(nullptr != userdata);
         if (this == userdata)
         {
            assert(0 == completionQueueEntry->flags);
            if (0 > completionQueueEntry->res) [[unlikely]]
            {
               log_system_error("[tcp_client] failed to read eventfd: ({}) - {}", -completionQueueEntry->res);
               unreachable();
            }
            uringListener.handle_event_completion();
            if (true == m_running) [[likely]]
            {
               prep_read_eventfd();
            }
            else if (0 < completionQueueEntry->res)
            {
               prep_close_eventfd();
            }
         }
         else
         {
            uringListener.handle_task_completion(std::bit_cast<intptr_t>(userdata), completionQueueEntry->res, completionQueueEntry->flags);
         }
         ++numberOfCompletionQueueEntriesRemoved;
      }
      io_uring_cq_advance(m_ring.get(), numberOfCompletionQueueEntriesRemoved);
      return m_tasksCount;
   }

   void stop() override
   {
      assert(true == m_running);
      m_running = false;
   }

   void wake() override
   {
      assert(-1 != m_eventfd);
      if (-1 == eventfd_write(m_eventfd, 1)) [[unlikely]]
      {
         log_system_error("[tcp_client] failed to raise eventfd: ({}) - {}", errno);
         unreachable();
      }
   }

private:
   std::unique_ptr<io_uring> m_ring{std::make_unique<io_uring>(),};
   std::unique_ptr<sigset_t> m_sigmask{std::make_unique<sigset_t>(),};
   intptr_t m_tasksCount{0,};
   int m_eventfd{-1,};
   bool m_running{true,};
   eventfd_t m_eventfdValue{0,};
   std::unique_ptr<memory_pool> m_tcpSocketOperationsMemoryPool{nullptr,};
   std::vector<iovec> m_registeredBuffers{};
   std::unique_ptr<memory_pool> m_tcpSocketDescriptorsMemoryPool{nullptr,};
   std::vector<int32_t> m_registeredSockets{};

   void prep_close_eventfd()
   {
      io_uring_prep_close_direct(std::addressof(submission_queue_entry(this)), 0);
   }

   void prep_read_eventfd()
   {
      auto &submissionQueueEntry{submission_queue_entry(this),};
      io_uring_prep_read_fixed(
         std::addressof(submissionQueueEntry),
         0,
         std::addressof(m_eventfdValue),
         sizeof(m_eventfdValue),
         0,
         0
      );
      submissionQueueEntry.flags |= IOSQE_FIXED_FILE;
   }

   void register_eventfd()
   {
      assert(-1 != m_eventfd);
      if (
         auto const returnCode{io_uring_register_files_update(m_ring.get(), 0, std::addressof(m_eventfd), 1),};
         0 > returnCode
      ) [[unlikely]]
      {
         log_system_error("[tcp_client] failed to register eventfd: ({}) - {}", -returnCode);
         unreachable();
      }
   }

   [[nodiscard]] io_uring_sqe &submission_queue_entry(void *userdata)
   {
      assert(nullptr != userdata);
      assert(nullptr != m_ring);
      auto *submissionQueueEntry{io_uring_get_sqe(m_ring.get()),};
      if (nullptr == submissionQueueEntry) [[unlikely]]
      {
         log_error(std::source_location::current(), "[tcp_client] failed to get submission queue entry, it must be a bug");
         unreachable();
      }
      io_uring_sqe_set_data(submissionQueueEntry, userdata);
      ++m_tasksCount;
      return *submissionQueueEntry;
   }
};

std::unique_ptr<tcp_client_uring> tcp_client_uring::construct(std::optional<uint16_t> const ioCpuAffinity, size_t const ioRingQueueCapacity)
{
   return std::make_unique<tcp_client_uring_impl>(ioCpuAffinity, ioRingQueueCapacity);
}

}
#endif
