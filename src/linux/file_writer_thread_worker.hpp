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

#include "common/file_writer_command.hpp" ///< for io_threads::file_writer_command
#include "common/logger.hpp" ///< for io_threads::log_error, io_threads::log_system_error
#include "common/memory_pool.hpp" ///< for io_threads::memory_pool
#include "common/thread_task.hpp" ///< for io_threads::thread_task
#include "common/utility.hpp" ///< for io_threads::to_underlying, io_threads::unreachable
#include "io_threads/file_writer.hpp" ///< for io_threads::file_writer
#include "io_threads/file_writer_option.hpp" ///< for io_threads::file_writer_option
#include "linux/file_descriptor.hpp" ///< for io_threads::file_descriptor, io_threads::file_status
#include "linux/uring_command_queue.hpp" ///< for io_threads::uring_command_queue
#include "linux/uring_stop_token.hpp" ///< for io_threads::uring_stop_token
#include "linux/uring_worker.hpp" ///< for io_threads::uring_worker

/// for
///   AT_FDCWD,
///   O_APPEND,
///   O_CREAT,
///   O_EXCL,
///   O_NONBLOCK,
///   O_TRUNC,
///   O_WRONLY,
///   S_IRWXG,
///   S_IRWXU
#include <fcntl.h>
/// for
///   io_uring_prep_close_direct,
///   io_uring_prep_fsync,
///   io_uring_prep_openat_direct,
///   io_uring_prep_write,
///   IOSQE_FIXED_FILE
#include <liburing.h>
#include <sched.h> ///< for CPU_SET, cpu_set_t, CPU_ZERO, sched_setaffinity

#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <cstddef> ///< for size_t
#include <cstdint> ///< for int32_t, intptr_t, uint16_t, uint32_t
#include <cstring> ///< for std::memcpy
#include <functional> ///< for std::function
#include <future> ///< for std::promise
#include <memory> ///< for std::addressof, std::make_unique, std::unique_ptr
#include <new> ///< for std::align_val_t, std::launder
#include <source_location> ///< for std::source_location
#include <stop_token> ///< for std::stop_token
#include <system_error> ///< for std::error_code, std::generic_category
#include <thread> ///< for std::jthread, std::this_thread

namespace io_threads
{

void set_thread_affinity(uint16_t const coreCpuId)
{
   cpu_set_t affinityMask;
   CPU_ZERO(std::addressof(affinityMask));
   CPU_SET(coreCpuId, std::addressof(affinityMask));
   if (auto const returnCode{sched_setaffinity(0, sizeof(affinityMask), std::addressof(affinityMask)),}; 0 != returnCode)
   {
      log_system_error(std::source_location::current(), "[file_writer] failed to pin thread to cpu core: ({}) - {}", returnCode);
      unreachable();
   }
}

class file_writer::file_writer_thread_worker final : public uring_listener
{
public:
   file_writer_thread_worker() = delete;
   file_writer_thread_worker(file_writer_thread_worker &&) = delete;
   file_writer_thread_worker(file_writer_thread_worker const &) = delete;

   file_writer_thread_worker &operator = (file_writer_thread_worker &&) = delete;
   file_writer_thread_worker &operator = (file_writer_thread_worker const &) = delete;

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
         assert(nullptr != m_uringCommandQueue);
         m_uringCommandQueue->push(static_cast<intptr_t>(file_writer_command::execute), std::bit_cast<intptr_t>(std::addressof(ioTask)));
         ioTask.completionFuture.wait();
      }
   }

   void ready_to_close(file_writer &fileWriter)
   {
      if (std::this_thread::get_id() == m_threadId)
      {
         handle_ready_to_close(fileWriter);
      }
      else
      {
         assert(nullptr != m_uringCommandQueue);
         m_uringCommandQueue->push(static_cast<intptr_t>(file_writer_command::ready_to_close), std::bit_cast<intptr_t>(std::addressof(fileWriter)));
      }
   }

   void ready_to_open(file_writer &fileWriter)
   {
      if (std::this_thread::get_id() == m_threadId)
      {
         handle_ready_to_open(fileWriter);
      }
      else
      {
         assert(nullptr != m_uringCommandQueue);
         m_uringCommandQueue->push(static_cast<intptr_t>(file_writer_command::ready_to_open), std::bit_cast<intptr_t>(std::addressof(fileWriter)));
      }
   }

   void ready_to_write(file_writer &fileWriter)
   {
      if (std::this_thread::get_id() == m_threadId)
      {
         handle_ready_to_write(fileWriter);
      }
      else
      {
         assert(nullptr != m_uringCommandQueue);
         m_uringCommandQueue->push(static_cast<intptr_t>(file_writer_command::ready_to_write), std::bit_cast<intptr_t>(std::addressof(fileWriter)));
      }
   }

   void stop()
   {
      assert(nullptr != m_uringCommandQueue);
      m_uringCommandQueue->push();
   }

   [[nodiscard]] static std::jthread start(
      uint16_t const coreCpuId,
      size_t const capacityOfFileDescriptorList,
      std::promise<file_writer_thread_worker &> &workerPromise
   )
   {
      return std::jthread
      {
         [coreCpuId, capacityOfFileDescriptorList, &workerPromise] (std::stop_token const stopToken)
         {
            set_thread_affinity(coreCpuId);
            file_writer_thread_worker threadWorker{stopToken, capacityOfFileDescriptorList,};
            assert(nullptr != threadWorker.m_uringWorker);
            assert(nullptr != threadWorker.m_uringCommandQueue);
            workerPromise.set_value(threadWorker);
            threadWorker.m_uringWorker->run(threadWorker.m_stopToken, *threadWorker.m_uringCommandQueue, threadWorker);
         }
      };
   }

private:
   std::unique_ptr<uring_worker> const m_uringWorker;
   uring_stop_token m_stopToken;
   std::jthread::id const m_threadId{std::this_thread::get_id(),};
   std::unique_ptr<uring_command_queue> const m_uringCommandQueue;
   file_descriptor *m_freeFileDescriptors{nullptr,};
   std::unique_ptr<memory_pool> const m_fileMemory;

   [[nodiscard]] file_writer_thread_worker(std::stop_token const &stopToken, size_t const capacityOfFileDescriptorList) :
      m_uringWorker{std::make_unique<uring_worker>(capacityOfFileDescriptorList, capacityOfFileDescriptorList + 1),},
      m_stopToken{stopToken,},
      m_uringCommandQueue{std::make_unique<uring_command_queue>(capacityOfFileDescriptorList),},
      m_fileMemory
      {
         std::make_unique<memory_pool>(
            capacityOfFileDescriptorList,
            std::align_val_t{alignof(file_descriptor),},
            sizeof(file_descriptor) + PATH_MAX
         )
      }
   {
      assert(0 < capacityOfFileDescriptorList);
      assert(nullptr != m_uringCommandQueue);
      for (
         uint32_t registeredFileIndex{static_cast<uint32_t>(capacityOfFileDescriptorList),};
         0 < registeredFileIndex;
         --registeredFileIndex
      )
      {
         m_freeFileDescriptors = std::addressof(
            m_fileMemory->pop_object<file_descriptor>(
               file_descriptor
               {
                  .registeredFileIndex = registeredFileIndex - 1,
                  .next = m_freeFileDescriptors,
               }
            )
         );
      }
   }

   ~file_writer_thread_worker()
   {
      while (nullptr != m_freeFileDescriptors)
      {
         auto *fileDescriptor{std::launder(m_freeFileDescriptors),};
         assert(file_status::none == fileDescriptor->fileStatus);
         assert(false == fileDescriptor->closeOnCompletion);
         assert(nullptr == fileDescriptor->fileWriter);
         m_freeFileDescriptors = fileDescriptor->next;
         m_fileMemory->push_object(*fileDescriptor);
      }
   }

   void close_file(file_writer &fileWriter)
   {
      assert(nullptr != fileWriter.m_fileDescriptor);
      assert(file_status::ready == fileWriter.m_fileDescriptor->fileStatus);
      assert(std::addressof(fileWriter) == fileWriter.m_fileDescriptor->fileWriter);
      assert(nullptr == fileWriter.m_fileDescriptor->next);
      auto &fileDescriptor{*fileWriter.m_fileDescriptor,};
      fileDescriptor.fileStatus = file_status::flushing;
      fileDescriptor.fileWriter = nullptr;
      fileWriter.m_fileDescriptor = nullptr;
      auto &submissionQueueEntry{m_uringWorker->submission_entry(std::addressof(fileDescriptor)),};
      submissionQueueEntry.len = 0;
      submissionQueueEntry.off = 0;
      io_uring_prep_fsync(std::addressof(submissionQueueEntry), fileDescriptor.registeredFileIndex, 0);
      submissionQueueEntry.flags |= IOSQE_FIXED_FILE;
      m_stopToken.increment_tasks_count();
   }

   void handle_command(intptr_t const commandId, intptr_t const commandTarget)
   {
      switch (commandId)
      {
      case to_underlying(file_writer_command::execute):
      {
         assert(0 != commandTarget);
         handle_thread_task(*std::bit_cast<thread_task *>(commandTarget));
      }
      break;

      case to_underlying(file_writer_command::ready_to_open):
      {
         assert(0 != commandTarget);
         handle_ready_to_open(*std::bit_cast<file_writer *>(commandTarget));
      }
      break;

      case to_underlying(file_writer_command::ready_to_write):
      {
         assert(0 != commandTarget);
         handle_ready_to_write(*std::bit_cast<file_writer *>(commandTarget));
      }
      break;

      case to_underlying(file_writer_command::ready_to_close):
      {
         assert(0 != commandTarget);
         handle_ready_to_close(*std::bit_cast<file_writer *>(commandTarget));
      }
      break;

      [[unlikely]] default:
      {
         log_error(std::source_location::current(), "[file_writer] unknown file_writer_command {}: it must be a bug", commandId);
         unreachable();
      }
      break;
      }
   }

   void handle_completion(intptr_t const userdata, int32_t const result, [[maybe_unused]] uint32_t const flags)
   {
      assert(0 != userdata);
      assert(0 == flags);
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
         m_stopToken.increment_tasks_count();
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
      m_stopToken.decrement_tasks_count();
   }

   void handle_ready_to_close(file_writer &fileWriter)
   {
      assert(nullptr != fileWriter.m_fileDescriptor);
      assert(false == fileWriter.m_fileDescriptor->closeOnCompletion);
      assert(std::addressof(fileWriter) == fileWriter.m_fileDescriptor->fileWriter);
      assert(nullptr == fileWriter.m_fileDescriptor->next);
      if (file_status::ready == fileWriter.m_fileDescriptor->fileStatus)
      {
         close_file(fileWriter);
         fileWriter.io_closed(std::error_code{});
      }
      else
      {
         assert(
            false
            || (file_status::opening == fileWriter.m_fileDescriptor->fileStatus)
            || (file_status::busy == fileWriter.m_fileDescriptor->fileStatus)
         );
         fileWriter.m_fileDescriptor->closeOnCompletion = true;
      }
   }

   void handle_ready_to_open(file_writer &fileWriter)
   {
      assert(nullptr == fileWriter.m_fileDescriptor);
      auto const config{fileWriter.io_ready_to_open(),};
      int flags{O_CREAT | O_NONBLOCK | O_WRONLY,};
      switch (config.option())
      {
      case file_writer_option::create_new:
      {
         flags |= O_EXCL;
      }
      break;

      case file_writer_option::create_or_open_and_truncate:
      {
         flags |= O_TRUNC;
      }
      break;

      case file_writer_option::create_or_open_for_append:
      {
         flags |= O_APPEND;
      }
      break;

      [[unlikely]] default:
      {
         log_error(std::source_location::current(), "[file_writer] unexpected option {}: it must be a bug", to_underlying(config.option()));
         unreachable();
      }
      }
      if (nullptr == m_freeFileDescriptors) [[unlikely]]
      {
         log_error(std::source_location::current(), "[file_writer] too few file descriptors provided, please increase capacity of file descriptor list");
         unreachable();
      }
      auto &fileDescriptor{*std::launder(m_freeFileDescriptors)};
      m_freeFileDescriptors = fileDescriptor.next;
      fileDescriptor.next = nullptr;
      assert(file_status::none == fileDescriptor.fileStatus);
      assert(false == fileDescriptor.closeOnCompletion);
      assert(nullptr == fileDescriptor.fileWriter);
      fileWriter.m_fileDescriptor = std::addressof(fileDescriptor);
      fileDescriptor.fileStatus = file_status::opening;
      fileDescriptor.fileWriter = std::addressof(fileWriter);
      auto &filePath = config.path().native();
      auto *filePathCopy = std::bit_cast<char *>(std::addressof(fileDescriptor) + 1);
      std::memcpy(filePathCopy, filePath.c_str(), filePath.size());
      filePathCopy[filePath.size()] = 0;
      io_uring_prep_openat_direct(
         std::addressof(m_uringWorker->submission_entry(std::addressof(fileDescriptor))),
         AT_FDCWD,
         filePathCopy,
         flags,
         S_IRWXU | S_IRWXG,
         fileDescriptor.registeredFileIndex
      );
      m_stopToken.increment_tasks_count();
   }

   void handle_ready_to_write(file_writer &fileWriter)
   {
      assert(nullptr != fileWriter.m_fileDescriptor);
      assert(false == fileWriter.m_fileDescriptor->closeOnCompletion);
      assert(std::addressof(fileWriter) == fileWriter.m_fileDescriptor->fileWriter);
      assert(nullptr == fileWriter.m_fileDescriptor->next);
      if (file_status::ready == fileWriter.m_fileDescriptor->fileStatus)
      {
         write(fileWriter);
      }
      else
      {
         assert(file_status::busy == fileWriter.m_fileDescriptor->fileStatus);
      }
   }

   void handle_thread_task(thread_task &task)
   {
      assert(task.routine);
      task.routine();
      task.completionPromise.set_value();
   }

   void write(file_writer &fileWriter)
   {
      assert(nullptr != fileWriter.m_fileDescriptor);
      auto &fileDescriptor{*fileWriter.m_fileDescriptor,};
      assert(file_status::ready == fileDescriptor.fileStatus);
      assert(std::addressof(fileWriter) == fileWriter.m_fileDescriptor->fileWriter);
      assert(nullptr == fileWriter.m_fileDescriptor->next);
      auto const dataChunk{fileWriter.io_ready_to_write(),};
      if (0 == dataChunk.bytesLength)
      {
         if (true == fileDescriptor.closeOnCompletion)
         {
            close_file(fileWriter);
            fileWriter.io_closed(std::error_code{});
         }
         return;
      }
      auto &submissionQueueEntry{m_uringWorker->submission_entry(std::addressof(fileDescriptor)),};
      fileDescriptor.fileStatus = file_status::busy;
      io_uring_prep_write(
         std::addressof(submissionQueueEntry),
         static_cast<int>(fileDescriptor.registeredFileIndex),
         dataChunk.bytes,
         static_cast<uint32_t>(dataChunk.bytesLength),
         -1
      );
      submissionQueueEntry.flags |= IOSQE_FIXED_FILE;
      m_stopToken.increment_tasks_count();
   }
};

}
