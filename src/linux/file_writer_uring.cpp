/*
   Part of the io_threads project (https://github.com/cpp4ever/io_threads), under the MIT License
   SPDX-License-Identifier: MIT

   Copyright (c) 2024-2025 Mikhail Smirnov

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
#include "common/utility.hpp" ///< for io_threads::to_underlying, io_threads::unreachable
#include "io_threads/thread_config.hpp" ///< for io_threads::io_affinity, io_threads::cpu_id, io_threads::io_ring
#include "linux/file_descriptor.hpp" ///< for io_threads::file_descriptor, io_threads::registered_buffer
#include "linux/file_writer_uring.hpp" ///< for io_threads::file_writer_uring
#include "linux/uring_listener.hpp" ///< for io_threads::uring_listener

#include <fcntl.h> ///< for AT_FDCWD
/// for
///   io_uring,
///   io_uring_cq_advance,
///   io_uring_cqe,
///   io_uring_cqe_get_data,
///   io_uring_for_each_cqe,
///   io_uring_get_sqe,
///   io_uring_params,
///   io_uring_prep_close_direct,
///   io_uring_prep_fsync,
///   io_uring_prep_openat_direct,
///   io_uring_prep_read_fixed,
///   io_uring_prep_write_fixed,
///   io_uring_queue_exit,
///   io_uring_queue_init_params,
///   io_uring_register_buffers,
///   io_uring_register_files,
///   io_uring_register_files_update,
///   io_uring_register_iowq_aff,
///   io_uring_register_iowq_max_workers,
///   io_uring_register_ring_fd,
///   io_uring_ring_dontfork,
///   io_uring_sqe_set_data,
///   io_uring_submit_and_wait_timeout,
///   io_uring_unregister_buffers,
///   io_uring_unregister_files,
///   io_uring_unregister_iowq_aff,
///   io_uring_unregister_ring_fd,
///   IORING_CQE_F_MORE,
///   IORING_FEAT_SINGLE_MMAP,
///   IORING_SETUP_ATTACH_WQ,
///   IORING_SETUP_CQSIZE,
///   IORING_SETUP_NO_SQARRAY,
///   IORING_SETUP_SINGLE_ISSUER,
///   IORING_SETUP_SQ_AFF,
///   IORING_SETUP_SQPOLL,
///   IOSQE_FIXED_FILE
#include <liburing.h>
#include <sched.h> ///< for CPU_SET, cpu_set_t, CPU_ZERO
#include <signal.h> ///< for sigset_t
#include <sys/eventfd.h> ///< for EFD_NONBLOCK, eventfd, eventfd_t, eventfd_write
#include <sys/types.h> ///< for mode_t
#include <sys/uio.h> ///< for iovec
#include <unistd.h> ///< for close

#include <array> ///< for std::array
#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <cerrno> ///< for errno
#include <cstdint> ///< for int32_t, intptr_t, uint32_t
#include <cstring> ///< for std::memset
#include <memory> ///< for std::addressof, std::make_unique, std::unique_ptr
#include <new> ///< for std::align_val_t
#include <optional> ///< for std::nullopt_t, std::optional
#include <source_location> ///< for std::source_location
#include <variant> ///< for std::visit
#include <vector> ///< for std::vector

namespace io_threads
{

class file_writer_uring_impl final : public file_writer_uring
{
private:
   using super = file_writer_uring;
   template<typename... types> struct overloaded : types... { using types::operator()...; };

public:
   file_writer_uring_impl() = delete;
   file_writer_uring_impl(file_writer_uring_impl &&) = delete;
   file_writer_uring_impl(file_writer_uring_impl const &) = delete;

   [[nodiscard]] file_writer_uring_impl(
      io_affinity const &asyncWorkersAffinity,
      io_affinity const &kernelThreadAffinity,
      uint32_t const ioRingQueueCapacity,
      uint32_t const ioBufferSize
   ) :
      super{},
      m_registeredBufferPool{ioRingQueueCapacity, std::align_val_t{alignof(registered_buffer),}, registered_buffer::total_size(ioBufferSize),},
      m_fileDescriptorPool{ioRingQueueCapacity, std::align_val_t{alignof(file_descriptor),}, sizeof(file_descriptor),}
   {
      assert(0 < ioRingQueueCapacity);
      assert(0 < ioBufferSize);
      io_uring_params ioRingParams;
      std::memset(std::addressof(ioRingParams), 0, sizeof(ioRingParams));
      ioRingParams.sq_entries = ioRingQueueCapacity + 1;
      ioRingParams.cq_entries = ioRingQueueCapacity * 2 + 1;
      ioRingParams.flags = IORING_SETUP_CQSIZE | IORING_SETUP_SINGLE_ISSUER;
#if (defined(IORING_SETUP_NO_SQARRAY))
      ioRingParams.flags |= IORING_SETUP_NO_SQARRAY;
#endif
      std::visit(
         overloaded
         {
            [] (std::nullopt_t const) {},

            [] (cpu_id const) {},

            [&ioRingParams] (io_ring const ioRing)
            {
               ioRingParams.flags |= IORING_SETUP_ATTACH_WQ;
               ioRingParams.wq_fd = to_underlying(ioRing);
            },
         },
         asyncWorkersAffinity
      );
      std::visit(
         overloaded
         {
            [] (std::nullopt_t const) {},

            [&ioRingParams] (cpu_id const kernelThreadCpuId)
            {
               ioRingParams.flags |= IORING_SETUP_SQPOLL | IORING_SETUP_SQ_AFF;
               ioRingParams.sq_thread_cpu = to_underlying(kernelThreadCpuId);
               ioRingParams.sq_thread_idle = 100;
            },

            [&ioRingParams] (io_ring const ioRing)
            {
               ioRingParams.flags |= IORING_SETUP_SQPOLL | IORING_SETUP_ATTACH_WQ;
               ioRingParams.wq_fd = to_underlying(ioRing);
            },
         },
         kernelThreadAffinity
      );
      ioRingParams.features = IORING_FEAT_SINGLE_MMAP;
      if (
         auto const returnCode{io_uring_queue_init_params(ioRingQueueCapacity + 1, std::addressof(m_ring), std::addressof(ioRingParams)),};
         0 > returnCode
      ) [[unlikely]]
      {
         log_system_error("[file_writer] failed to initialize the ring: ({}) - {}", -returnCode);
         unreachable();
      }
      if (auto const returnCode{io_uring_register_ring_fd(std::addressof(m_ring)),}; 0 > returnCode) [[unlikely]]
      {
         log_system_error("[file_writer] failed to register ring descriptor: ({}) - {}", -returnCode);
      }
      std::visit(
         overloaded
         {
            [] (std::nullopt_t const) {},

            [this] (cpu_id const asyncWorkersCpuId)
            {
               cpu_set_t iowqAffinityMask;
               CPU_ZERO(std::addressof(iowqAffinityMask));
               CPU_SET(to_underlying(asyncWorkersCpuId), std::addressof(iowqAffinityMask));
               if (auto const returnCode{io_uring_register_iowq_aff(std::addressof(m_ring), sizeof(iowqAffinityMask), std::addressof(iowqAffinityMask)),}; 0 > returnCode) [[unlikely]]
               {
                  log_system_error("[file_writer] failed to register IO workers affinity mask: ({}) - {}", -returnCode);
               }
            },

            [] (io_ring const) {},
         },
         asyncWorkersAffinity
      );
      std::array<uint32_t, 2> iowqMaxWorkers = {ioRingQueueCapacity, ioRingQueueCapacity,};
      if (auto const returnCode{io_uring_register_iowq_max_workers(std::addressof(m_ring), iowqMaxWorkers.data()),}; 0 > returnCode) [[unlikely]]
      {
         log_system_error("[file_writer] failed to register IO workers limits: ({}) - {}", -returnCode);
      }
      if (auto const returnCode{io_uring_ring_dontfork(std::addressof(m_ring)),}; 0 > returnCode) [[unlikely]]
      {
         log_system_error("[file_writer] failed to disable inheriting of the ring mappings: ({}) - {}", -returnCode);
      }
      if (-1 == (m_eventfd = eventfd(0, EFD_NONBLOCK))) [[unlikely]]
      {
         log_system_error("[file_writer] failed to create eventfd: ({}) - {}", errno);
         unreachable();
      }
   }

   ~file_writer_uring_impl() override
   {
      assert(0 == m_tasksCount);
      assert(-1 != m_eventfd);
      if (-1 == close(m_eventfd)) [[unlikely]]
      {
         log_system_error("[file_writer] failed to destroy eventfd: ({}) - {}", errno);
      }
      if (auto const returnCode{io_uring_unregister_iowq_aff(std::addressof(m_ring)),}; 0 > returnCode) [[unlikely]]
      {
         log_system_error("[file_writer] failed to unregister IO workers affinity mask: ({}) - {}", -returnCode);
      }
      if (auto const returnCode{io_uring_unregister_ring_fd(std::addressof(m_ring)),}; 0 > returnCode) [[unlikely]]
      {
         log_system_error("[file_writer] failed to unregister ring descriptor: ({}) - {}", -returnCode);
      }
      io_uring_queue_exit(std::addressof(m_ring));
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

   [[nodiscard]] registered_buffer *register_buffers(uint32_t const fileListCapacity) override
   {
      assert(0 < fileListCapacity);
      assert(true == m_registeredBuffers.empty());
      m_registeredBuffers.reserve(fileListCapacity + 1);
      registered_buffer *registeredBuffers{nullptr,};
      for (auto registeredBufferIndex{fileListCapacity,}; 0 < registeredBufferIndex; --registeredBufferIndex)
      {
         registeredBuffers = std::addressof(
            m_registeredBufferPool.pop_object<registered_buffer>(
               registered_buffer{.next = registeredBuffers, .index = registeredBufferIndex,}
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
         auto const returnCode{io_uring_register_buffers(std::addressof(m_ring), m_registeredBuffers.data(), m_registeredBuffers.size()),};
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
      assert(true == m_registeredFiles.empty());
      m_registeredFiles.resize(fileListCapacity + 1, -1);
      if (
         auto const returnCode{io_uring_register_files(std::addressof(m_ring), m_registeredFiles.data(), static_cast<uint32_t>(m_registeredFiles.size())),};
         0 > returnCode
      ) [[unlikely]]
      {
         log_system_error("[file_writer] failed to register files: ({}) - {}", -returnCode);
         unreachable();
      }
      file_descriptor *fileDescriptors{nullptr,};
      for (auto registeredFileIndex{fileListCapacity,}; 0 < registeredFileIndex; --registeredFileIndex)
      {
         fileDescriptors = std::addressof(
            m_fileDescriptorPool.pop_object<file_descriptor>(
               file_descriptor{.registeredFileIndex = registeredFileIndex, .next = fileDescriptors,}
            )
         );
      }
      return fileDescriptors;
   }

   [[nodiscard]] uint32_t registered_buffer_capacity(registered_buffer &) const override
   {
      return registered_buffer::bytes_size(m_registeredBufferPool.memory_chunk_size());
   }

   void unregister_buffers(registered_buffer *registeredBuffers) override
   {
      assert(nullptr != registeredBuffers);
      assert(false == m_registeredBuffers.empty());
      if (auto const returnCode{io_uring_unregister_buffers(std::addressof(m_ring)),}; 0 > returnCode) [[unlikely]]
      {
         log_system_error("[file_writer] failed to unregister memory buffers: ({}) - {}", -returnCode);
         unreachable();
      }
      while (nullptr != registeredBuffers)
      {
         auto *registeredBuffer{registeredBuffers,};
         registeredBuffers = registeredBuffer->next;
         registeredBuffer->next = nullptr;
         m_registeredBufferPool.push_object(*registeredBuffer);
      }
      m_registeredBuffers.clear();
   }

   void unregister_file_descriptors(file_descriptor *fileDescriptors) override
   {
      assert(nullptr != fileDescriptors);
      assert(false == m_registeredFiles.empty());
      if (auto const returnCode{io_uring_unregister_files(std::addressof(m_ring)),}; 0 > returnCode) [[unlikely]]
      {
         log_system_error("[file_writer] failed to unregister files: ({}) - {}", -returnCode);
      }
      while (nullptr != fileDescriptors)
      {
         auto *fileDescriptor{fileDescriptors,};
         assert(file_status::none == fileDescriptor->fileStatus);
         assert(false == fileDescriptor->closeOnCompletion);
         assert(nullptr == fileDescriptor->registeredBufferInFlight);
         assert(nullptr == fileDescriptor->fileWriter);
         fileDescriptors = fileDescriptor->next;
         fileDescriptor->next = nullptr;
         m_fileDescriptorPool.push_object(*fileDescriptor);
      }
      m_registeredFiles.clear();
   }

   void run(uring_listener &uringListener, sigset_t &sigmask) override
   {
      register_eventfd();
      prep_read_eventfd();
      while (0 < m_tasksCount) [[likely]]
      {
         poll(uringListener, sigmask);
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

   [[nodiscard]] io_ring share_io_threads() const noexcept override
   {
      return io_ring{m_ring.ring_fd,};
   }

private:
   io_uring m_ring{};
   intptr_t m_tasksCount{0,};
   int m_eventfd{-1,};
   bool m_running{true,};
   eventfd_t m_eventfdValue{0,};
   memory_pool m_registeredBufferPool;
   std::vector<iovec> m_registeredBuffers{};
   memory_pool m_fileDescriptorPool;
   std::vector<int32_t> m_registeredFiles{};

   void poll(uring_listener &uringListener, sigset_t &sigmask)
   {
      io_uring_cqe *completionQueueEntry{nullptr,};
      if (
         auto const returnCode{io_uring_submit_and_wait_timeout(std::addressof(m_ring), std::addressof(completionQueueEntry), 1, nullptr, std::addressof(sigmask)),};
         0 > returnCode
      ) [[unlikely]]
      {
         log_system_error("[file_writer] failed to submit prepared tasks: ({}) - {}", -returnCode);
         unreachable();
      }
      uint32_t completionQueueHead;
      uint32_t numberOfCompletionQueueEntriesRemoved{0,};
      io_uring_for_each_cqe(std::addressof(m_ring), completionQueueHead, completionQueueEntry)
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
      io_uring_cq_advance(std::addressof(m_ring), numberOfCompletionQueueEntriesRemoved);
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
         auto const returnCode{io_uring_register_files_update(std::addressof(m_ring), 0, std::addressof(m_eventfd), 1),};
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
      auto *submissionQueueEntry{io_uring_get_sqe(std::addressof(m_ring)),};
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

std::unique_ptr<file_writer_uring> file_writer_uring::construct(
   io_affinity const &asyncWorkersAffinity,
   io_affinity const &kernelThreadAffinity,
   uint32_t const ioRingQueueCapacity,
   uint32_t const ioBufferSize
)
{
   return std::make_unique<file_writer_uring_impl>(asyncWorkersAffinity, kernelThreadAffinity, ioRingQueueCapacity, ioBufferSize);
}

}
#endif
