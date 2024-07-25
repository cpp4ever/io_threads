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
#include "io_threads/file_writer_config.hpp" ///< for io_threads::file_writer_option
#include "linux/file_descriptor.hpp" ///< for io_threads::file_descriptor, io_threads::file_status
#include "linux/file_writer_uring.hpp" ///< for io_threads::file_writer_uring
#include "linux/thread_affinity.hpp" ///< for io_threads::set_thread_affinity
#include "linux/uring_command_queue.hpp" ///< for io_threads::uring_command_queue
#include "linux/uring_listener.hpp" ///< for io_threads::uring_listener

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

#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <climits> ///< for PATH_MAX
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

class file_writer::file_writer_thread_worker final : public uring_listener
{
public:
   file_writer_thread_worker() = delete;
   file_writer_thread_worker(file_writer_thread_worker &&) = delete;
   file_writer_thread_worker(file_writer_thread_worker const &) = delete;

   [[nodiscard]] file_writer_thread_worker(
      std::unique_ptr<file_writer_uring> fileWriterUring,
      size_t const fileListCapacity,
      size_t const ioBufferCapacity
   ) :
      m_uringCommandQueue{fileListCapacity,},
      m_fileWriterUring{std::move(fileWriterUring),}
   {
      m_registeredBuffers = m_fileWriterUring->register_buffers(
         fileListCapacity,
         std::max(registered_buffer::calc_total_size(PATH_MAX + 1), registered_buffer::calc_total_size(ioBufferCapacity))
      );
      assert(nullptr != m_registeredBuffers);
      m_fileDescriptors = m_fileWriterUring->register_file_descriptors(fileListCapacity);
      assert(nullptr != m_fileDescriptors);
   }

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
         m_uringCommandQueue.push(static_cast<intptr_t>(file_writer_command::execute), std::bit_cast<intptr_t>(std::addressof(ioTask)));
         m_fileWriterUring->wake();
         ioTask.completionFuture.wait();
      }
   }

   void ready_to_close(file_writer &fileWriter)
   {
      m_uringCommandQueue.push(static_cast<intptr_t>(file_writer_command::ready_to_close), std::bit_cast<intptr_t>(std::addressof(fileWriter)));
      m_fileWriterUring->wake();
   }

   void ready_to_open(file_writer &fileWriter)
   {
      m_uringCommandQueue.push(static_cast<intptr_t>(file_writer_command::ready_to_open), std::bit_cast<intptr_t>(std::addressof(fileWriter)));
      m_fileWriterUring->wake();
   }

   void ready_to_write(file_writer &fileWriter)
   {
      m_uringCommandQueue.push(static_cast<intptr_t>(file_writer_command::ready_to_write), std::bit_cast<intptr_t>(std::addressof(fileWriter)));
      m_fileWriterUring->wake();
   }

   void stop()
   {
      m_uringCommandQueue.push(static_cast<intptr_t>(file_writer_command::unknown), 0);
      m_fileWriterUring->wake();
   }

   [[nodiscard]] static std::jthread start(
      file_writer_thread_config const &fileWriterThreadConfig,
      std::promise<std::shared_ptr<file_writer_thread_worker>> &workerPromise
   )
   {
      return std::jthread
      {
         [fileWriterThreadConfig, &workerPromise] (std::stop_token const)
         {
            if (true == fileWriterThreadConfig.poll_cpu_affinity().has_value())
            {
               if (auto const returnCode{set_thread_affinity(fileWriterThreadConfig.poll_cpu_affinity().value()),}; 0 != returnCode)
               {
                  log_system_error("[file_writer] failed to pin thread to cpu core: ({}) - {}", returnCode);
                  unreachable();
               }
            }
            auto const threadWorker
            {
               std::make_shared<file_writer_thread_worker>(
                  file_writer_uring::construct(fileWriterThreadConfig.io_cpu_affinity(), fileWriterThreadConfig.file_list_capacity() + 1),
                  fileWriterThreadConfig.file_list_capacity(),
                  fileWriterThreadConfig.io_buffer_capacity()
               ),
            };
            workerPromise.set_value(threadWorker);
            threadWorker->m_fileWriterUring->run(*threadWorker);
            threadWorker->m_fileWriterUring->unregister_file_descriptors(threadWorker->m_fileDescriptors);
            threadWorker->m_fileDescriptors = nullptr;
            threadWorker->m_fileWriterUring->unregister_buffers(threadWorker->m_registeredBuffers);
            threadWorker->m_registeredBuffers = nullptr;
         }
      };
   }

private:
   std::jthread::id const m_threadId{std::this_thread::get_id(),};
   uring_command_queue m_uringCommandQueue;
   std::unique_ptr<file_writer_uring> const m_fileWriterUring;
   registered_buffer *m_registeredBuffers{nullptr,};
   file_descriptor *m_fileDescriptors{nullptr,};

   void close_file(file_writer &fileWriter)
   {
      assert(nullptr != fileWriter.m_fileDescriptor);
      auto &fileDescriptor{*fileWriter.m_fileDescriptor,};
      assert(0 < fileDescriptor.registeredFileIndex);
      assert(file_status::ready == fileDescriptor.fileStatus);
      assert(nullptr == fileDescriptor.registeredBufferInFlight);
      assert(std::addressof(fileWriter) == fileDescriptor.fileWriter);
      assert(nullptr == fileDescriptor.next);
      fileDescriptor.fileStatus = file_status::fsync;
      m_fileWriterUring->prep_fsync(fileDescriptor);
   }

   void handle_command(intptr_t const commandId, intptr_t const commandTarget) override
   {
      assert(std::this_thread::get_id() == m_threadId);
      switch (commandId)
      {
      [[unlikely]] case to_underlying(file_writer_command::unknown):
      {
         assert(0 == commandTarget);
         m_fileWriterUring->stop();
      }
      break;

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
      }
   }

   void handle_event_completion() override
   {
      assert(std::this_thread::get_id() == m_threadId);
      m_uringCommandQueue.handle(*this);
   }

   void handle_ready_to_close(file_writer &fileWriter)
   {
      auto *fileDescriptor{fileWriter.m_fileDescriptor,};
      if (nullptr != fileDescriptor) [[likely]]
      {
         assert(0 < fileDescriptor->registeredFileIndex);
         assert(file_status::none != fileDescriptor->fileStatus);
         assert(std::addressof(fileWriter) == fileDescriptor->fileWriter);
         assert(nullptr == fileDescriptor->next);
         fileDescriptor->closeOnCompletion = true;
         if ((file_status::ready == fileDescriptor->fileStatus) && (nullptr == fileDescriptor->registeredBufferInFlight))
         {
            close_file(fileWriter);
         }
      }
   }

   void handle_ready_to_open(file_writer &fileWriter)
   {
      assert(nullptr == fileWriter.m_fileDescriptor);
      file_writer_config const config{fileWriter.io_ready_to_open(),};
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
      if (nullptr == m_fileDescriptors) [[unlikely]]
      {
         log_error(std::source_location::current(), "[file_writer] too few file descriptors provided, please increase capacity of file descriptor list");
         unreachable();
      }
      auto &fileDescriptor{*std::launder(m_fileDescriptors)};
      m_fileDescriptors = std::launder(fileDescriptor.next);
      fileDescriptor.next = nullptr;
      assert(0 < fileDescriptor.registeredFileIndex);
      assert(file_status::none == fileDescriptor.fileStatus);
      assert(false == fileDescriptor.closeOnCompletion);
      assert(nullptr == fileDescriptor.registeredBufferInFlight);
      assert(nullptr == fileDescriptor.fileWriter);
      assert(false == (bool{fileDescriptor.closeReason,}));
      fileWriter.m_fileDescriptor = std::addressof(fileDescriptor);
      fileDescriptor.fileStatus = file_status::open;
      fileDescriptor.fileWriter = std::addressof(fileWriter);
      auto &registeredBuffer{pop_registered_buffer(fileDescriptor),};
      assert(std::addressof(registeredBuffer) == fileDescriptor.registeredBufferInFlight);
      auto &filePath = config.path().native();
      assert(PATH_MAX >= filePath.size());
      std::memcpy(std::addressof(registeredBuffer.bytes[0]), filePath.data(), filePath.size());
      registeredBuffer.bytes[filePath.size()] = std::byte{0,};
      m_fileWriterUring->prep_open(fileDescriptor, flags, S_IRWXU | S_IRWXG);
   }

   void handle_ready_to_write(file_writer &fileWriter)
   {
      auto const *fileDescriptor{fileWriter.m_fileDescriptor,};
      if (nullptr != fileDescriptor) [[likely]]
      {
         assert(0 < fileDescriptor->registeredFileIndex);
         assert(file_status::none != fileDescriptor->fileStatus);
         assert(false == fileDescriptor->closeOnCompletion);
         assert(std::addressof(fileWriter) == fileDescriptor->fileWriter);
         assert(nullptr == fileDescriptor->next);
         if ((file_status::ready == fileDescriptor->fileStatus) && (nullptr == fileDescriptor->registeredBufferInFlight))
         {
            write(fileWriter);
         }
      }
   }

   void handle_task_completion(intptr_t const userdata, int32_t const result, [[maybe_unused]] uint32_t const flags) override
   {
      assert(0 != userdata);
      assert(0 == flags);
      auto &fileDescriptor{*std::launder(std::bit_cast<file_descriptor *>(userdata)),};
      assert(0 < fileDescriptor.registeredFileIndex);
      assert(file_status::none != fileDescriptor.fileStatus);
      assert(nullptr != fileDescriptor.fileWriter);
      auto &fileWriter = *fileDescriptor.fileWriter;
      assert(std::addressof(fileDescriptor) == fileWriter.m_fileDescriptor);
      assert(nullptr == fileDescriptor.next);
      assert(std::this_thread::get_id() == m_threadId);
      switch (fileDescriptor.fileStatus)
      {
      case file_status::open:
      {
         push_registered_buffer(fileDescriptor);
         assert(nullptr == fileDescriptor.registeredBufferInFlight);
         if (0 <= result) [[likely]]
         {
            fileDescriptor.fileStatus = file_status::ready;
            fileWriter.io_opened();
            if (nullptr == fileDescriptor.registeredBufferInFlight)
            {
               write(fileWriter);
            }
         }
         else
         {
            fileDescriptor.closeReason = std::error_code{-result, std::generic_category(),};
            push_file_descriptor(fileDescriptor);
         }
      }
      break;

      [[likely]] case file_status::ready:
      {
         push_registered_buffer(fileDescriptor);
         assert(nullptr == fileDescriptor.registeredBufferInFlight);
         if (0 <= result) [[likely]]
         {
            write(fileWriter);
         }
         else
         {
            fileDescriptor.closeReason = std::error_code{-result, std::generic_category(),};
            close_file(fileWriter);
         }
      }
      break;

      case file_status::fsync:
      {
         if (0 > result) [[unlikely]]
         {
            log_system_error("[file_writer] failed to sync file buffers: ({}) - {}", -result);
         }
         fileDescriptor.fileStatus = file_status::close;
         m_fileWriterUring->prep_close(fileDescriptor);
      }
      break;

      case file_status::close:
      {
         if (0 > result) [[unlikely]]
         {
            log_system_error("[file_writer] failed to close file: ({}) - {}", -result);
         }
         push_file_descriptor(fileDescriptor);
      }
      break;

      [[unlikely]] case file_status::none: [[fallthrough]];
      [[unlikely]] default:
      unreachable();
      }
   }

   void handle_thread_task(thread_task &task)
   {
      assert(task.routine);
      task.routine();
      task.completionPromise.set_value();
   }

   [[nodiscard]] registered_buffer &pop_registered_buffer(file_descriptor &fileDescriptor)
   {
      assert(0 < fileDescriptor.registeredFileIndex);
      assert(file_status::none != fileDescriptor.fileStatus);
      assert(file_status::fsync != fileDescriptor.fileStatus);
      assert(file_status::close != fileDescriptor.fileStatus);
      assert(nullptr == fileDescriptor.registeredBufferInFlight);
      assert(nullptr != fileDescriptor.fileWriter);
      assert(std::addressof(fileDescriptor) == fileDescriptor.fileWriter->m_fileDescriptor);
      assert(nullptr == fileDescriptor.next);
      assert(false == (bool{fileDescriptor.closeReason,}));
      assert(nullptr != m_registeredBuffers);
      auto &registeredBuffer{*std::launder(m_registeredBuffers),};
      assert(0 < registeredBuffer.index);
      m_registeredBuffers = std::launder(registeredBuffer.next);
      registeredBuffer.next = nullptr;
      fileDescriptor.registeredBufferInFlight = std::addressof(registeredBuffer);
      return registeredBuffer;
   }

   void push_file_descriptor(file_descriptor &fileDescriptor)
   {
      assert(0 < fileDescriptor.registeredFileIndex);
      assert(file_status::none != fileDescriptor.fileStatus);
      assert(file_status::ready != fileDescriptor.fileStatus);
      assert(file_status::fsync != fileDescriptor.fileStatus);
      assert(nullptr == fileDescriptor.registeredBufferInFlight);
      assert(nullptr != fileDescriptor.fileWriter);
      assert(nullptr == fileDescriptor.next);
      auto &fileWriter = *fileDescriptor.fileWriter;
      assert(std::addressof(fileDescriptor) == fileWriter.m_fileDescriptor);
      fileWriter.m_fileDescriptor = nullptr;
      fileDescriptor.fileStatus = file_status::none;
      fileDescriptor.closeOnCompletion = false;
      fileDescriptor.fileWriter = nullptr;
      fileDescriptor.next = std::launder(m_fileDescriptors);
      auto const closeReason{fileDescriptor.closeReason,};
      fileDescriptor.closeReason = std::error_code{};
      m_fileDescriptors = std::launder(std::addressof(fileDescriptor));
      fileWriter.io_closed(closeReason);
   }

   void push_registered_buffer(file_descriptor &fileDescriptor)
   {
      assert(0 < fileDescriptor.registeredFileIndex);
      assert(file_status::none != fileDescriptor.fileStatus);
      assert(file_status::fsync != fileDescriptor.fileStatus);
      assert(file_status::close != fileDescriptor.fileStatus);
      assert(nullptr != fileDescriptor.registeredBufferInFlight);
      assert(nullptr != fileDescriptor.fileWriter);
      assert(nullptr == fileDescriptor.next);
      assert(false == (bool{fileDescriptor.closeReason,}));
      auto &registeredBuffer{*std::launder(fileDescriptor.registeredBufferInFlight),};
      fileDescriptor.registeredBufferInFlight = nullptr;
      assert(0 < registeredBuffer.index);
      assert(nullptr == registeredBuffer.next);
      registeredBuffer.next = std::launder(m_registeredBuffers);
      m_registeredBuffers = std::launder(std::addressof(registeredBuffer));
   }

   void write(file_writer &fileWriter)
   {
      assert(nullptr != fileWriter.m_fileDescriptor);
      auto &fileDescriptor{*fileWriter.m_fileDescriptor,};
      assert(0 < fileDescriptor.registeredFileIndex);
      assert(file_status::ready == fileDescriptor.fileStatus);
      assert(nullptr == fileDescriptor.registeredBufferInFlight);
      assert(std::addressof(fileWriter) == fileWriter.m_fileDescriptor->fileWriter);
      assert(nullptr == fileWriter.m_fileDescriptor->next);
      assert(false == (bool{fileDescriptor.closeReason,}));
      auto &registeredBuffer{pop_registered_buffer(fileDescriptor),};
      assert(std::addressof(registeredBuffer) == fileDescriptor.registeredBufferInFlight);
      auto const bytesWritten
      {
         fileWriter.io_ready_to_write(
            data_chunk
            {
               .bytes = std::addressof(registeredBuffer.bytes[0]),
               .bytesLength = m_fileWriterUring->registered_buffer_capacity(registeredBuffer),
            }
         ),
      };
      if (0 < bytesWritten)
      {
         m_fileWriterUring->prep_write(fileDescriptor, bytesWritten);
      }
      else
      {
         push_registered_buffer(fileDescriptor);
         assert(nullptr == fileDescriptor.registeredBufferInFlight);
         if (true == fileDescriptor.closeOnCompletion) [[unlikely]]
         {
            close_file(fileWriter);
         }
      }
   }
};

}
