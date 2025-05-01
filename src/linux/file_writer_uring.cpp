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
#include "linux/file_descriptor.hpp" ///< for io_threads::file_descriptor
#include "linux/file_writer_uring.hpp" ///< for io_threads::file_writer_uring
#include "linux/uring_listener.hpp" ///< for io_threads::uring_listener

#include <errno.h> ///< for errno
#include <liburing.h>
#include <sched.h> ///< for CPU_SET, cpu_set_t, CPU_ZERO
#include <signal.h> ///< for sigfillset, sigset_t
#include <sys/eventfd.h> ///< for EFD_NONBLOCK, eventfd, eventfd_t, eventfd_write

#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <cstddef> ///< for size_t
#include <cstdint> ///< for int32_t, intptr_t, uint32_t
#include <memory> ///< for std::addressof, std::make_unique, std::unique_ptr
#include <new> ///< for std::align_val_t
#include <optional> ///< for std::optional
#include <source_location> ///< for std::source_location
#include <vector> ///< for std::vector

namespace io_threads
{

class file_writer_uring_impl final : public file_writer_uring
{
public:
   file_writer_uring_impl() = delete;
   file_writer_uring_impl(file_writer_uring_impl &&) = delete;
   file_writer_uring_impl(file_writer_uring_impl const &) = delete;

   [[nodiscard]] file_writer_uring_impl(std::optional<uint16_t> const ioCpuAffinity, size_t const ioRingQueueCapacity)
   {
      assert(0 < ioRingQueueCapacity);
      assert(nullptr != m_ring);
      if (
         auto const returnCode{io_uring_queue_init(ioRingQueueCapacity, m_ring.get(), IORING_SETUP_SINGLE_ISSUER),};
         0 > returnCode
      ) [[unlikely]]
      {
         log_system_error("[file_writer] failed to initialize the ring: ({}) - {}", -returnCode);
         unreachable();
      }
      if (auto const returnCode{io_uring_register_ring_fd(m_ring.get()),}; 0 > returnCode) [[unlikely]]
      {
         log_system_error("[file_writer] failed to register ring descriptor: ({}) - {}", -returnCode);
      }
      if (true == ioCpuAffinity.has_value())
      {
         cpu_set_t iowqAffinityMask;
         CPU_ZERO(std::addressof(iowqAffinityMask));
         CPU_SET(ioCpuAffinity.value(), std::addressof(iowqAffinityMask));
         if (auto const returnCode{io_uring_register_iowq_aff(m_ring.get(), sizeof(iowqAffinityMask), std::addressof(iowqAffinityMask)),}; 0 > returnCode) [[unlikely]]
         {
            log_system_error("[file_writer] failed to register IO workers affinity mask: ({}) - {}", -returnCode);
         }
      }
      std::array<uint32_t, 2> iowqMaxWorkers = {static_cast<uint32_t>(ioRingQueueCapacity), static_cast<uint32_t>(ioRingQueueCapacity),};
      if (auto const returnCode{io_uring_register_iowq_max_workers(m_ring.get(), iowqMaxWorkers.data()),}; 0 > returnCode) [[unlikely]]
      {
         log_system_error("[file_writer] failed to register IO workers limits: ({}) - {}", -returnCode);
      }
      if (auto const returnCode{io_uring_ring_dontfork(m_ring.get()),}; 0 > returnCode) [[unlikely]]
      {
         log_system_error("[file_writer] failed to disable inheriting of the ring mappings: ({}) - {}", -returnCode);
      }
      if (-1 == sigfillset(m_sigmask.get())) [[unlikely]]
      {
         log_system_error("[file_writer] failed to initialize sigmask: ({}) - {}", errno);
         unreachable();
      }
      if (-1 == (m_eventfd = eventfd(0, EFD_NONBLOCK))) [[unlikely]]
      {
         log_system_error("[file_writer] failed to create eventfd: ({}) - {}", errno);
         unreachable();
      }
   }

   ~file_writer_uring_impl() override
   {
      assert(nullptr != m_ring);
      assert(0 == m_tasksCount);
      assert(-1 != m_eventfd);
      if (-1 == close(m_eventfd)) [[unlikely]]
      {
         log_system_error("[file_writer] failed to destroy eventfd: ({}) - {}", errno);
      }
      if (auto const returnCode{io_uring_unregister_iowq_aff(m_ring.get()),}; 0 > returnCode) [[unlikely]]
      {
         log_system_error("[file_writer] failed to unregister IO workers affinity mask: ({}) - {}", -returnCode);
      }
      if (auto const returnCode{io_uring_unregister_ring_fd(m_ring.get()),}; 0 > returnCode) [[unlikely]]
      {
         log_system_error("[file_writer] failed to unregister ring descriptor: ({}) - {}", -returnCode);
      }
      io_uring_queue_exit(m_ring.get());
   }

   file_writer_uring_impl &operator = (file_writer_uring_impl &&) = delete;
   file_writer_uring_impl &operator = (file_writer_uring_impl const &) = delete;

   void prep_close(file_descriptor &fileDescriptor) override
   {
      assert(0 < fileDescriptor.registeredFileIndex);
      assert(nullptr == fileDescriptor.registeredBufferInFlight);
      io_uring_prep_close_direct(
         std::addressof(submission_queue_entry(std::addressof(fileDescriptor))),
         fileDescriptor.registeredFileIndex
      );
   }

   void prep_fsync(file_descriptor &fileDescriptor) override
   {
      assert(0 < fileDescriptor.registeredFileIndex);
      assert(nullptr == fileDescriptor.registeredBufferInFlight);
      auto &submissionQueueEntry{submission_queue_entry(std::addressof(fileDescriptor)),};
      submissionQueueEntry.len = 0;
      submissionQueueEntry.off = 0;
      io_uring_prep_fsync(std::addressof(submissionQueueEntry), fileDescriptor.registeredFileIndex, 0);
      submissionQueueEntry.flags |= IOSQE_FIXED_FILE;
   }

   void prep_open(file_descriptor &fileDescriptor, int32_t const flags, mode_t const mode) override
   {
      assert(0 < fileDescriptor.registeredFileIndex);
      assert(nullptr != fileDescriptor.registeredBufferInFlight);
      auto &registeredBuffer{*fileDescriptor.registeredBufferInFlight,};
      io_uring_prep_openat_direct(
         std::addressof(submission_queue_entry(std::addressof(fileDescriptor))),
         AT_FDCWD,
         std::bit_cast<char const *>(std::addressof(registeredBuffer.bytes[0])),
         flags,
         mode,
         fileDescriptor.registeredFileIndex
      );
   }

   void prep_write(file_descriptor &fileDescriptor, uint32_t const bytesLength) override
   {
      assert(0 < fileDescriptor.registeredFileIndex);
      assert(nullptr != fileDescriptor.registeredBufferInFlight);
      auto &registeredBuffer{*fileDescriptor.registeredBufferInFlight,};
      assert(0 < registeredBuffer.index);
      assert(0 < bytesLength);
      auto &submissionQueueEntry{submission_queue_entry(std::addressof(fileDescriptor)),};
      io_uring_prep_write_fixed(
         std::addressof(submissionQueueEntry),
         static_cast<int>(fileDescriptor.registeredFileIndex),
         registeredBuffer.bytes,
         bytesLength,
         -1,
         static_cast<int>(registeredBuffer.index)
      );
      submissionQueueEntry.flags |= IOSQE_FIXED_FILE;
   }

   [[nodiscard]] registered_buffer *register_buffers(uint32_t const fileListCapacity, size_t const registeredBufferCapacity) override
   {
      assert(0 < fileListCapacity);
      assert(sizeof(registered_buffer) <= registeredBufferCapacity);
      assert(nullptr != m_ring);
      assert(nullptr == m_registeredBuffersMemoryPool);
      assert(true == m_registeredBuffers.empty());
      m_registeredBuffersMemoryPool = std::make_unique<memory_pool>(
         fileListCapacity,
         std::align_val_t{alignof(registered_buffer),},
         registeredBufferCapacity
      );
      m_registeredBuffers.reserve(fileListCapacity + 1);
      registered_buffer *registeredBuffers{nullptr,};
      for (auto registeredBufferIndex{fileListCapacity,}; 0 < registeredBufferIndex; --registeredBufferIndex)
      {
         registeredBuffers = std::addressof(
            m_registeredBuffersMemoryPool->pop_object<registered_buffer>(
               registered_buffer{.next = std::launder(registeredBuffers), .index = registeredBufferIndex,}
            )
         );
      }
      m_registeredBuffers.push_back(iovec{.iov_base = std::addressof(m_eventfdValue), .iov_len = sizeof(m_eventfdValue),});
      for (auto *registeredBuffer = registeredBuffers; nullptr != registeredBuffer; registeredBuffer = registeredBuffer->next)
      {
         m_registeredBuffers.push_back(
            iovec{.iov_base = registeredBuffer->bytes, .iov_len = registered_buffer_capacity(*registeredBuffer),}
         );
      }
      if (
         auto const returnCode{io_uring_register_buffers(m_ring.get(), m_registeredBuffers.data(), m_registeredBuffers.size()),};
         0 > returnCode
      ) [[unlikely]]
      {
         log_system_error("[file_writer] failed to register memory buffers: ({}) - {}", -returnCode);
         unreachable();
      }
      return registeredBuffers;
   }

   [[nodiscard]] file_descriptor *register_file_descriptors(uint32_t const fileListCapacity) override
   {
      assert(0 < fileListCapacity);
      assert(nullptr != m_ring);
      assert(nullptr == m_fileDescriptorsMemoryPool);
      assert(true == m_registeredFiles.empty());
      m_registeredFiles.resize(fileListCapacity + 1, -1);
      if (
         auto const returnCode{io_uring_register_files(m_ring.get(), m_registeredFiles.data(), static_cast<uint32_t>(m_registeredFiles.size())),};
         0 > returnCode
      ) [[unlikely]]
      {
         log_system_error("[file_writer] failed to register files: ({}) - {}", -returnCode);
         unreachable();
      }
      m_fileDescriptorsMemoryPool = std::make_unique<memory_pool>(
         fileListCapacity,
         std::align_val_t{alignof(file_descriptor),},
         sizeof(file_descriptor)
      );
      file_descriptor *fileDescriptors{nullptr,};
      for (auto registeredFileIndex{fileListCapacity,}; 0 < registeredFileIndex; --registeredFileIndex)
      {
         fileDescriptors = std::addressof(
            m_fileDescriptorsMemoryPool->pop_object<file_descriptor>(
               file_descriptor{.registeredFileIndex = registeredFileIndex, .next = std::launder(fileDescriptors),}
            )
         );
      }
      return fileDescriptors;
   }

   [[nodiscard]] size_t registered_buffer_capacity(registered_buffer &) const override
   {
      assert(nullptr != m_registeredBuffersMemoryPool);
      return registered_buffer::calc_bytes_capacity(m_registeredBuffersMemoryPool->memory_chunk_size());
   }

   void unregister_buffers(registered_buffer *registeredBuffers) override
   {
      assert(nullptr != registeredBuffers);
      assert(nullptr != m_ring);
      assert(nullptr != m_registeredBuffersMemoryPool);
      assert(false == m_registeredBuffers.empty());
      if (auto const returnCode{io_uring_unregister_buffers(m_ring.get()),}; 0 > returnCode) [[unlikely]]
      {
         log_system_error("[file_writer] failed to unregister memory buffers: ({}) - {}", -returnCode);
         unreachable();
      }
      while (nullptr != registeredBuffers)
      {
         auto *registeredBuffer{std::launder(registeredBuffers),};
         registeredBuffers = std::launder(registeredBuffer->next);
         registeredBuffer->next = nullptr;
         m_registeredBuffersMemoryPool->push_object(*registeredBuffer);
      }
      m_registeredBuffers.clear();
      m_registeredBuffersMemoryPool.reset();
   }

   void unregister_file_descriptors(file_descriptor *fileDescriptors) override
   {
      assert(nullptr != fileDescriptors);
      assert(nullptr != m_ring);
      assert(nullptr != m_fileDescriptorsMemoryPool);
      assert(false == m_registeredFiles.empty());
      if (auto const returnCode{io_uring_unregister_files(m_ring.get()),}; 0 > returnCode) [[unlikely]]
      {
         log_system_error("[file_writer] failed to unregister files: ({}) - {}", -returnCode);
      }
      while (nullptr != fileDescriptors)
      {
         auto *fileDescriptor{std::launder(fileDescriptors),};
         assert(file_status::none == fileDescriptor->fileStatus);
         assert(false == fileDescriptor->closeOnCompletion);
         assert(nullptr == fileDescriptor->registeredBufferInFlight);
         assert(nullptr == fileDescriptor->fileWriter);
         fileDescriptors = std::launder(fileDescriptor->next);
         fileDescriptor->next = nullptr;
         m_fileDescriptorsMemoryPool->push_object(*fileDescriptor);
      }
      m_registeredFiles.clear();
      m_fileDescriptorsMemoryPool.reset();
   }

   void run(uring_listener &uringListener) override
   {
      assert(nullptr != m_ring);
      register_eventfd();
      prep_read_eventfd();
      while (0 < m_tasksCount) [[likely]]
      {
         poll(uringListener);
      }
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
         log_system_error("[file_writer] failed to raise eventfd: ({}) - {}", errno);
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
   std::unique_ptr<memory_pool> m_registeredBuffersMemoryPool{nullptr,};
   std::vector<iovec> m_registeredBuffers{};
   std::unique_ptr<memory_pool> m_fileDescriptorsMemoryPool{nullptr,};
   std::vector<int32_t> m_registeredFiles{};

   void poll(uring_listener &uringListener)
   {
      io_uring_cqe *completionQueueEntry{nullptr,};
      if (
         auto const returnCode{io_uring_submit_and_wait_timeout(m_ring.get(), std::addressof(completionQueueEntry), 1, nullptr, m_sigmask.get()),};
         0 > returnCode
      ) [[unlikely]]
      {
         log_system_error("[file_writer] failed to submit prepared tasks: ({}) - {}", -returnCode);
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
               log_system_error("[file_writer] failed to handle eventfd: ({}) - {}", -completionQueueEntry->res);
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
   }

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
         log_system_error("[file_writer] failed to register eventfd: ({}) - {}", -returnCode);
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
         log_error(std::source_location::current(), "[file_writer] failed to get submission queue entry, it must be a bug");
         unreachable();
      }
      io_uring_sqe_set_data(submissionQueueEntry, userdata);
      ++m_tasksCount;
      return *submissionQueueEntry;
   }
};

std::unique_ptr<file_writer_uring> file_writer_uring::construct(std::optional<uint16_t> const ioCpuAffinity, size_t const ioRingQueueCapacity)
{
   return std::make_unique<file_writer_uring_impl>(ioCpuAffinity, ioRingQueueCapacity);
}

}
#endif
