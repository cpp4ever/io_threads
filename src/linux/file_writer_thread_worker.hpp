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
#include "common/logger.hpp" ///< for io_threads::log_system_error
#include "common/memory_pool.hpp" ///< for io_threads::memory_pool
#include "common/shared_memory_pool.hpp" ///< for io_threads::shared_memory_pool
#include "common/thread_task.hpp" ///< for io_threads::thread_task
#include "common/utility.hpp" ///< for io_threads::to_underlying, io_threads::unreachable
#include "io_threads/file_writer.hpp" ///< for io_threads::file_writer
#include "io_threads/file_writer_option.hpp" ///< for io_threads::file_writer_option
#include "linux/file_descriptor.hpp" ///< for io_threads::file_descriptor

#include <liburing.h>
#include <poll.h>
#include <sys/eventfd.h>

#include <cassert> ///< for assert
#include <cstddef> ///< for size_t
#include <cstdint> ///< for uint16_t
#include <functional> ///< for std::function
#include <future> ///< for std::promise
#include <memory> ///< for std::addressof, std::make_unique, std::unique_ptr
#include <new> ///< for std::align_val_t
#include <source_location> ///< for std::source_location
#include <stop_token> ///< for std::stop_token
#include <system_error> ///< for std::error_code
#include <thread> ///< for std::jthread, std::this_thread

namespace io_threads
{

template<typename command_enum>
class command_queue final
{
private:
   struct queue_item final
   {
      queue_item *next{nullptr,};
      intptr_t commandTarget{0,};
      command_enum command{command_enum::unknown,};
   };

public:
   command_queue() = delete;
   command_queue(command_queue &&) = delete;
   command_queue(command_queue const &) = delete;

   [[nodiscard]] explicit command_queue(size_t const initialCapacityOfCommandQueue) :
      m_memoryPool{initialCapacityOfCommandQueue, std::align_val_t{alignof(queue_item)}, sizeof(queue_item)}
   {}

   command_queue &operator = (command_queue &&) = delete;
   command_queue &operator = (command_queue const &) = delete;

   template<typename task_handler>
   void pop(task_handler &&taskHandler)
   {
      queue_item *orderedTasks{nullptr,};
      auto *unorderedTasks{m_tasksHead.exchange(nullptr, std::memory_order_relaxed)};
      while (nullptr != unorderedTasks)
      {
         auto *task{std::launder(unorderedTasks)};
         unorderedTasks = task->next;
         task->next = orderedTasks;
         orderedTasks = task;
      }
      while (nullptr != orderedTasks)
      {
         auto *task{std::launder(orderedTasks)};
         orderedTasks = task->next;
         taskHandler(task->command, task->commandTarget);
         m_memoryPool.push_object(*task);
      }
   }

   void push(command_enum const command, intptr_t const commandTarget)
   {
      auto &task = m_memoryPool.pop_object<queue_item>(
         queue_item
         {
            .next = m_tasksHead.load(std::memory_order_relaxed),
            .commandTarget = commandTarget,
            .command = command,
         }
      );
      while (
         false == m_tasksHead.compare_exchange_strong(
            task.next,
            std::addressof(task),
            std::memory_order_release,
            std::memory_order_relaxed
         )
      )
      {}
   }

private:
   shared_memory_pool m_memoryPool;
   std::atomic<queue_item *> m_tasksHead{nullptr};
};

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

class file_writer::file_writer_thread_worker final
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
         assert(nullptr != m_commandQueue);
         m_commandQueue->push(file_writer_command::execute, std::bit_cast<intptr_t>(std::addressof(ioTask)));
         wake_up_ring();
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
         assert(nullptr != m_commandQueue);
         m_commandQueue->push(file_writer_command::ready_to_close, std::bit_cast<intptr_t>(std::addressof(fileWriter)));
         wake_up_ring();
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
         assert(nullptr != m_commandQueue);
         m_commandQueue->push(file_writer_command::ready_to_open, std::bit_cast<intptr_t>(std::addressof(fileWriter)));
         wake_up_ring();
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
         assert(nullptr != m_commandQueue);
         m_commandQueue->push(file_writer_command::ready_to_write, std::bit_cast<intptr_t>(std::addressof(fileWriter)));
         wake_up_ring();
      }
   }

   void stop()
   {
      wake_up_ring();
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
            file_writer_thread_worker worker{capacityOfFileDescriptorList,};
            assert(nullptr != worker.m_ring);
            assert(nullptr != worker.m_commandQueue);
            workerPromise.set_value(worker);
            sigset_t sigmask{};
            if (-1 == sigfillset(std::addressof(sigmask))) [[unlikely]]
            {
               log_system_error(std::source_location::current(), "[file_writer] failed to initialize sigmask: ({}) - {}", errno);
               unreachable();
            }
            {
               auto *submissionQueueEntry = io_uring_get_sqe(worker.m_ring.get());
               if (nullptr == submissionQueueEntry) [[unlikely]]
               {
                  log_error(std::source_location::current(), "[file_writer] failed to get submission queue entry");
                  unreachable();
               }
               io_uring_sqe_set_data(submissionQueueEntry, worker.m_commandQueue.get());
               io_uring_prep_poll_multishot(submissionQueueEntry, worker.m_eventfd, POLLIN);
            }
            while (false == stopToken.stop_requested()) [[likely]]
            {
               worker.poll(sigmask);
            }
            {
               auto *submissionQueueEntry = io_uring_get_sqe(worker.m_ring.get());
               if (nullptr == submissionQueueEntry) [[unlikely]]
               {
                  log_error(std::source_location::current(), "[file_writer] failed to get submission queue entry");
                  unreachable();
               }
               io_uring_prep_poll_remove(submissionQueueEntry, static_cast<uint64_t>(std::bit_cast<uintptr_t>(worker.m_commandQueue.get())));
            }
            worker.poll(sigmask);
         }
      };
   }

private:
   std::jthread::id const m_threadId{std::this_thread::get_id(),};
   std::unique_ptr<io_uring> m_ring{std::make_unique<io_uring>(),};
   std::unique_ptr<command_queue<file_writer_command>> const m_commandQueue;
   file_descriptor *m_freeFileDescriptors{nullptr,};
   std::vector<int> m_registeredFiles{};
   std::unique_ptr<memory_pool> const m_fileMemory;
   int m_eventfd{-1,};

   [[nodiscard]] explicit file_writer_thread_worker(size_t const capacityOfFileDescriptorList) :
      m_commandQueue{std::make_unique<command_queue<file_writer_command>>(capacityOfFileDescriptorList),},
      m_fileMemory
      {
         std::make_unique<memory_pool>(
            capacityOfFileDescriptorList,
            std::align_val_t{alignof(file_descriptor),},
            sizeof(file_descriptor)
         )
      }
   {
      assert(0 < capacityOfFileDescriptorList);
      assert(nullptr != m_ring);
      assert(nullptr != m_commandQueue);
      if (
         auto const returnCode{io_uring_queue_init(capacityOfFileDescriptorList + 1, m_ring.get(), IORING_SETUP_SINGLE_ISSUER),};
         0 > returnCode
      ) [[unlikely]]
      {
         log_system_error(std::source_location::current(), "[file_writer] failed to initialize io_uring: ({}) - {}", -returnCode);
         unreachable();
      }
      m_registeredFiles.resize(capacityOfFileDescriptorList, 0);
      if (
         auto const returnCode{io_uring_register_files(m_ring.get(), m_registeredFiles.data(), static_cast<uint32_t>(m_registeredFiles.size())),};
         0 > returnCode
      ) [[unlikely]]
      {
         log_system_error(std::source_location::current(), "[file_writer] failed to register files: ({}) - {}", -returnCode);
         unreachable();
      }
      if (-1 == (m_eventfd = eventfd(0, EFD_NONBLOCK))) [[unlikely]]
      {
         log_system_error(std::source_location::current(), "[file_writer] failed to open eventfd: ({}) - {}", errno);
         unreachable();
      }
      for (
         uint32_t registeredFileIndex{static_cast<uint32_t>(m_registeredFiles.size()),};
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
      if (-1 == close(m_eventfd)) [[unlikely]]
      {
         log_system_error(std::source_location::current(), "[file_writer] failed to close eventfd: ({}) - {}", errno);
      }
      assert(nullptr != m_ring);
      if (auto const returnCode{io_uring_unregister_files(m_ring.get()),}; 0 > returnCode)
      {
         log_system_error(std::source_location::current(), "[file_writer] failed to unregister files: ({}) - {}", -returnCode);
      }
      io_uring_queue_exit(m_ring.get());
   }

   void close_file(file_writer &fileWriter)
   {
      assert(nullptr != fileWriter.m_fileDescriptor);
      assert(file_status::ready == fileWriter.m_fileDescriptor->fileStatus);
      assert(std::addressof(fileWriter) == fileWriter.m_fileDescriptor->fileWriter);
      assert(nullptr == fileWriter.m_fileDescriptor->next);
      auto *submissionQueueEntry = io_uring_get_sqe(m_ring.get());
      if (nullptr == submissionQueueEntry) [[unlikely]]
      {
         log_error(std::source_location::current(), "[file_writer] failed to get submission queue entry");
         unreachable();
      }
      auto &fileDescriptor{*fileWriter.m_fileDescriptor,};
      io_uring_sqe_set_data(submissionQueueEntry, std::addressof(fileDescriptor));
      fileDescriptor.fileStatus = file_status::flushing;
      fileDescriptor.fileWriter = nullptr;
      submissionQueueEntry->len = 0;
      submissionQueueEntry->off = 0;
      io_uring_prep_fsync(submissionQueueEntry, fileDescriptor.registeredFileIndex, 0);
      io_uring_sqe_set_flags(submissionQueueEntry, IOSQE_FIXED_FILE);
   }

   void handle_command(file_writer_command const command, intptr_t const commandTarget)
   {
      switch (command)
      {
      case file_writer_command::unknown:
      {
         assert(0 == commandTarget);
      }
      break;

      case file_writer_command::execute:
      {
         assert(0 != commandTarget);
         handle_thread_task(*std::bit_cast<thread_task *>(commandTarget));
      }
      break;

      case file_writer_command::ready_to_open:
      {
         assert(0 != commandTarget);
         handle_ready_to_open(*std::bit_cast<file_writer *>(commandTarget));
      }
      break;

      case file_writer_command::ready_to_write:
      {
         assert(0 != commandTarget);
         handle_ready_to_write(*std::bit_cast<file_writer *>(commandTarget));
      }
      break;

      case file_writer_command::ready_to_close:
      {
         assert(0 != commandTarget);
         handle_ready_to_close(*std::bit_cast<file_writer *>(commandTarget));
      }
      break;

      [[unlikely]] default:
      {
         log_error(std::source_location::current(), "[file_writer] unknown file_writer_command {}: it must be a bug", to_underlying(command));
         unreachable();
      }
      break;
      }
   }

   void handle_operation_completion(file_descriptor &fileDescriptor, int const returnCode)
   {
      assert(file_status::none != fileDescriptor.fileStatus);
      assert(nullptr == fileDescriptor.next);
      if (nullptr != fileDescriptor.fileWriter) [[likely]]
      {
         if (file_status::busy == fileDescriptor.fileStatus) [[likely]]
         {
            fileDescriptor.fileStatus = file_status::ready;
            auto &fileWriter = *fileDescriptor.fileWriter;
            assert(std::addressof(fileDescriptor) == fileWriter.m_fileDescriptor);
            if (0 == returnCode) [[likely]]
            {
               write(fileWriter);
            }
            else
            {
               close_file(fileWriter);
               std::error_code errorCode{-returnCode, std::system_category(),};
               fileWriter.io_closed(errorCode);
            }
         }
         else
         {
            assert(file_status::opening == fileDescriptor.fileStatus);
            fileDescriptor.fileStatus = file_status::ready;
            auto &fileWriter = *fileDescriptor.fileWriter;
            assert(std::addressof(fileDescriptor) == fileWriter.m_fileDescriptor);
            if (0 == returnCode) [[likely]]
            {
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
               std::error_code errorCode{-returnCode, std::system_category(),};
               fileWriter.io_closed(errorCode);
            }
         }
      }
      else if (file_status::flushing == fileDescriptor.fileStatus)
      {
         if (0 != returnCode) [[unlikely]]
         {
            log_system_error(std::source_location::current(), "[file_writer] failed to flush file buffers: ({}) - {}", -returnCode);
         }
         auto *submissionQueueEntry = io_uring_get_sqe(m_ring.get());
         if (nullptr == submissionQueueEntry) [[unlikely]]
         {
            log_error(std::source_location::current(), "[file_writer] failed to get submission queue entry");
            unreachable();
         }
         io_uring_sqe_set_data(submissionQueueEntry, std::addressof(fileDescriptor));
         fileDescriptor.fileStatus = file_status::closing;
         io_uring_prep_close_direct(submissionQueueEntry, fileDescriptor.registeredFileIndex);
      }
      else if (file_status::closing == fileDescriptor.fileStatus)
      {
         if (0 != returnCode) [[unlikely]]
         {
            log_system_error(std::source_location::current(), "[file_writer] failed to close file: ({}) - {}", -returnCode);
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
      auto const config{fileWriter.io_ready_to_open()};
      int flags = O_CREAT | O_NONBLOCK | O_WRONLY;
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
         log_error(
            std::source_location::current(),
            "[file_writer] unexpected option {}: it must be a bug",
            to_underlying(config.option())
         );
         unreachable();
      }
      }
      if (nullptr == m_freeFileDescriptors) [[unlikely]]
      {
         log_error(
            std::source_location::current(),
            "[file_writer] too few file descriptors provided, please increase capacity of file descriptor list"
         );
         unreachable();
      }
      auto *submissionQueueEntry = io_uring_get_sqe(m_ring.get());
      if (nullptr == submissionQueueEntry) [[unlikely]]
      {
         log_error(std::source_location::current(), "[file_writer] failed to get submission queue entry");
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
      io_uring_sqe_set_data(submissionQueueEntry, std::addressof(fileDescriptor));
      io_uring_prep_openat_direct(submissionQueueEntry, AT_FDCWD, config.path().c_str(), flags, S_IRWXU | S_IRWXG, fileDescriptor.registeredFileIndex);
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

   void poll(sigset_t &sigmask)
   {
      assert(nullptr != m_ring);
      if (auto const returnCode{io_uring_submit(m_ring.get()),}; 0 > returnCode) [[unlikely]]
      {
         log_system_error(std::source_location::current(), "[file_writer] failed to submit prepared tasks: ({}) - {}", -returnCode);
         unreachable();
      }
      io_uring_cqe *completionQueueEntry{nullptr,};
      if (
         auto const returnCode{io_uring_wait_cqes(m_ring.get(), std::addressof(completionQueueEntry), 1, nullptr,std::addressof(sigmask)),};
         0 > returnCode
      ) [[unlikely]]
      {
         log_system_error(std::source_location::current(), "[file_writer] failed to wait for completion queue entry: ({}) - {}", -returnCode);
         unreachable();
      }
      uint32_t completionQueueHead;
      uint32_t numberOfCompletionQueueEntriesRemoved{0,};
      io_uring_for_each_cqe(m_ring.get(), completionQueueHead, completionQueueEntry)
      {
         auto *userdata{io_uring_cqe_get_data(completionQueueEntry),};
         assert(nullptr != userdata);
         if (m_commandQueue.get() == userdata)
         {
            eventfd_t eventfdValue{0,};
            if (-1 == eventfd_read(m_eventfd, std::addressof(eventfdValue))) [[unlikely]]
            {
               log_system_error(std::source_location::current(), "[file_writer] failed to reset eventfd: ({}) - {}", errno);
               unreachable();
            }
            m_commandQueue->pop(
               [this] (auto const command, auto const commandTarget)
               {
                  handle_command(command, commandTarget);
               }
            );
         }
         else
         {
            handle_operation_completion(*std::bit_cast<file_descriptor *>(userdata), completionQueueEntry->res);
         }
         ++numberOfCompletionQueueEntriesRemoved;
      }
      io_uring_cq_advance(m_ring.get(), numberOfCompletionQueueEntriesRemoved);
   }

   void wake_up_ring()
   {
      if (-1 == eventfd_write(m_eventfd, 1)) [[unlikely]]
      {
         log_system_error(std::source_location::current(), "[file_writer] failed to raise eventfd: ({}) - {}", errno);
         unreachable();
      }
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
      auto *submissionQueueEntry = io_uring_get_sqe(m_ring.get());
      if (nullptr == submissionQueueEntry) [[unlikely]]
      {
         log_error(std::source_location::current(), "[file_writer] failed to get submission queue entry");
         unreachable();
      }
      io_uring_sqe_set_data(submissionQueueEntry, std::addressof(fileDescriptor));
      fileDescriptor.fileStatus = file_status::busy;
      io_uring_prep_write(
         submissionQueueEntry,
         static_cast<int>(fileDescriptor.registeredFileIndex),
         dataChunk.bytes,
         static_cast<uint32_t>(dataChunk.bytesLength),
         -1
      );
      io_uring_sqe_set_flags(submissionQueueEntry, IOSQE_FIXED_FILE);
   }
};

}
