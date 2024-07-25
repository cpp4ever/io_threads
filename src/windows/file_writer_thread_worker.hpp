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
#include "common/thread_task.hpp" ///< for io_threads::thread_task
#include "common/utility.hpp" ///< for io_threads::to_underlying, io_threads::unreachable
#include "io_threads/file_writer.hpp" ///< for io_threads::file_writer
#include "io_threads/file_writer_option.hpp" ///< for io_threads::file_writer_option
/// for
///   io_threads::completion_port,
///   io_threads::from_completion_key,
///   io_threads::to_completion_key
#include "windows/completion_port.hpp"
#include "windows/file_descriptor.hpp" ///< for io_threads::file_descriptor
/// for
///   io_threads::file_writer_command,
///   io_threads::from_completion_overlapped,
///   io_threads::to_completion_overlapped
#include "windows/file_writer_command.hpp"
#include "windows/winapi_error.hpp" ///< for io_threads::check_winapi_error, io_threads::check_winapi_error_if_not

/// for
///   CloseHandle,
///   CREATE_ALWAYS,
///   CREATE_NEW,
///   CreateFileW,
///   DWORD,
///   DWORD_PTR,
///   ERROR_IO_PENDING,
///   FALSE,
///   FILE_ATTRIBUTE_NORMAL,
///   FILE_FLAG_OVERLAPPED,
///   FILE_SHARE_READ,
///   FILE_WRITE_DATA,
///   FlushFileBuffers,
///   GetCurrentThread,
///   GetOverlappedResult,
///   HANDLE,
///   INVALID_HANDLE_VALUE,
///   LocalFree,
///   MAXDWORD,
///   OPEN_ALWAYS,
///   OVERLAPPED_ENTRY,
///   SECURITY_ATTRIBUTES,
///   SetThreadAffinityMask,
///   TEXT,
///   TRUE,
///   WCHAR,
///   WriteFile
#include <Windows.h>
#include <sddl.h> ///< for ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1

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

#pragma comment(lib, "AdvAPI32")
#pragma comment(lib, "kernel32")

namespace io_threads
{

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
         m_completionPort.post_queued_completion_status(
            to_completion_key(ioTask),
            to_completion_overlapped(file_writer_command::execute)
         );
         ioTask.completionFuture.wait();
      }
   }

   void ready_to_close(file_writer &writer)
   {
      if (std::this_thread::get_id() == m_threadId)
      {
         handle_ready_to_close(writer);
      }
      else
      {
         m_completionPort.post_queued_completion_status(
            to_completion_key(writer),
            to_completion_overlapped(file_writer_command::ready_to_close)
         );
      }
   }

   void ready_to_open(file_writer &writer)
   {
      if (std::this_thread::get_id() == m_threadId)
      {
         handle_ready_to_open(writer);
      }
      else
      {
         m_completionPort.post_queued_completion_status(
            to_completion_key(writer),
            to_completion_overlapped(file_writer_command::ready_to_open)
         );
      }
   }

   void ready_to_write(file_writer &writer)
   {
      if (std::this_thread::get_id() == m_threadId)
      {
         handle_ready_to_write(writer);
      }
      else
      {
         m_completionPort.post_queued_completion_status(
            to_completion_key(writer),
            to_completion_overlapped(file_writer_command::ready_to_write)
         );
      }
   }

   void stop()
   {
      m_completionPort.post_queued_completion_status(0, to_completion_overlapped(file_writer_command::unknown));
   }

   [[nodiscard]] static std::jthread start(
      uint16_t const coreCpuId,
      size_t const initialCapacityOfFileDescriptorList,
      std::promise<file_writer_thread_worker &> &workerPromise
   )
   {
      return std::jthread
      {
         [coreCpuId, initialCapacityOfFileDescriptorList, &workerPromise] (std::stop_token const stopToken)
         {
            if (0 == SetThreadAffinityMask(GetCurrentThread(), static_cast<DWORD_PTR>(1) << coreCpuId)) [[unlikely]]
            {
               check_winapi_error("[file_writer] failed to pin thread to cpu core: ({}) - {}");
            }
            file_writer_thread_worker worker{initialCapacityOfFileDescriptorList};
            workerPromise.set_value(worker);
            while (false == stopToken.stop_requested()) [[likely]]
            {
               auto timeoutMilliseconds{completion_port::infinite_timeout};
               while (worker.m_completionPortEntries->size() == worker.poll(timeoutMilliseconds))
               {
                  /// Do while there are entries to poll
                  timeoutMilliseconds = completion_port::no_timeout;
               }
            }
            while (0 != worker.poll(completion_port::no_timeout))
            {
               /// Until all entries are polled
            }
         }
      };
   }

private:
   std::jthread::id const m_threadId{std::this_thread::get_id()};
   completion_port m_completionPort{};
   std::unique_ptr<completion_port::entries> const m_completionPortEntries;
   std::unique_ptr<memory_pool> const m_fileMemory;
   SECURITY_ATTRIBUTES m_securityAttributes
   {
      .nLength = sizeof(SECURITY_ATTRIBUTES),
      .lpSecurityDescriptor = nullptr,
      .bInheritHandle = FALSE,
   };

   [[nodiscard]] explicit file_writer_thread_worker(size_t const initialCapacityOfFileDescriptorList) :
      m_completionPortEntries{std::make_unique<completion_port::entries>()},
      m_fileMemory
      {
         std::make_unique<memory_pool>(
            initialCapacityOfFileDescriptorList,
            std::align_val_t{alignof(file_descriptor)},
            sizeof(file_descriptor)
         )
      }
   {
      constexpr WCHAR stringSecurityDescriptor[]
      {
         TEXT(L"D:")                    ///< Discretionary ACL
         TEXT(L"(D;OICI;GA;;;BG)")      ///< Deny access to built-in guests
         TEXT(L"(D;OICI;GA;;;AN)")      ///< Deny access to anonymous logon
         TEXT(L"(A;OICI;GRGWGX;;;AU)")  ///< Allow read/write/execute to authenticated users
         TEXT(L"(A;OICI;GA;;;BA)")      ///< Allow full control to administrators
      };
      if (
         FALSE == ConvertStringSecurityDescriptorToSecurityDescriptorW(
            stringSecurityDescriptor,
            SDDL_REVISION_1,
            std::addressof(m_securityAttributes.lpSecurityDescriptor),
            nullptr
         )
      ) [[unlikely]]
      {
         check_winapi_error("[file_writer] failed to create security descriptor: ({}) - {}");
      }
   }

   ~file_writer_thread_worker()
   {
      if (nullptr != LocalFree(m_securityAttributes.lpSecurityDescriptor)) [[unlikely]]
      {
         check_winapi_error("[file_writer] failed to free security descriptor: ({}) - {}");
      }
   }

   void close_file(file_writer &writer)
   {
      assert(nullptr != writer.m_fileDescriptor);
      auto &fileDescriptor{*writer.m_fileDescriptor};
      assert(false == fileDescriptor.busy);
      if (FALSE == FlushFileBuffers(fileDescriptor.handle)) [[unlikely]]
      {
         check_winapi_error("[file_writer] failed to flush file buffers: ({}) - {}");
      }
      if (FALSE == CloseHandle(fileDescriptor.handle)) [[unlikely]]
      {
         check_winapi_error("[file_writer] failed to close file: ({}) - {}");
      }
      m_fileMemory->push_object(fileDescriptor);
      writer.m_fileDescriptor = nullptr;
   }

   void handle_completion_port_entry(OVERLAPPED_ENTRY const &completionPortEntry)
   {
      switch (from_completion_overlapped(completionPortEntry.lpOverlapped))
      {
      case file_writer_command::unknown:
      {
         assert(0 == completionPortEntry.lpCompletionKey);
      }
      break;

      case file_writer_command::execute:
      {
         assert(0 != completionPortEntry.lpCompletionKey);
         handle_thread_task(*from_completion_key<thread_task>(completionPortEntry.lpCompletionKey));
      }
      break;

      case file_writer_command::ready_to_open:
      {
         assert(0 != completionPortEntry.lpCompletionKey);
         handle_ready_to_open(*from_completion_key<file_writer>(completionPortEntry.lpCompletionKey));
      }
      break;

      case file_writer_command::ready_to_write:
      {
         assert(0 != completionPortEntry.lpCompletionKey);
         handle_ready_to_write(*from_completion_key<file_writer>(completionPortEntry.lpCompletionKey));
      }
      break;

      case file_writer_command::ready_to_close:
      {
         assert(0 != completionPortEntry.lpCompletionKey);
         handle_ready_to_close(*from_completion_key<file_writer>(completionPortEntry.lpCompletionKey));
      }
      break;

      default:
      {
         /// Generated by WriteFile
         assert(0 != completionPortEntry.lpCompletionKey);
         auto *writer{from_completion_key<file_writer>(completionPortEntry.lpCompletionKey)};
         assert(nullptr != writer->m_fileDescriptor);
         if (std::addressof(writer->m_fileDescriptor->overlapped) == completionPortEntry.lpOverlapped) [[likely]]
         {
            handle_write_completion(*writer);
         }
         else
         {
            log_error(
               std::source_location::current(),
               "[file_writer] unexpected completion overlapped: it must be a bug"
            );
            unreachable();
         }
      }
      break;
      }
   }

   void handle_ready_to_close(file_writer &writer)
   {
      assert(nullptr != writer.m_fileDescriptor);
      assert(false == writer.m_fileDescriptor->closeOnCompletion);
      if (false == writer.m_fileDescriptor->busy)
      {
         close_file(writer);
         writer.io_closed(std::error_code{});
      }
      else
      {
         writer.m_fileDescriptor->closeOnCompletion = true;
      }
   }

   void handle_ready_to_open(file_writer &writer)
   {
      assert(nullptr == writer.m_fileDescriptor);
      auto const config{writer.io_ready_to_open()};
      auto const fileHandle
      {
         CreateFileW(
            config.path().c_str(),
            FILE_WRITE_DATA,
            FILE_SHARE_READ,
            std::addressof(m_securityAttributes),
            file_writer_option_to_creation_disposition(config.option()),
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
            nullptr
         )
      };
      if (INVALID_HANDLE_VALUE != fileHandle) [[likely]]
      {
         m_completionPort.add_handle(fileHandle, to_completion_key(writer));
         auto &fileDescriptor{m_fileMemory->pop_object<file_descriptor>()};
         assert(INVALID_HANDLE_VALUE == fileDescriptor.handle);
         assert(false == fileDescriptor.busy);
         fileDescriptor.handle = fileHandle;
         fileDescriptor.overlapped.Offset = fileDescriptor.overlapped.OffsetHigh = MAXDWORD;
         writer.m_fileDescriptor = std::addressof(fileDescriptor);
         writer.io_opened();
         write(writer);
      }
      else
      {
         writer.io_closed(check_winapi_error("[file_writer] failed to create/open file: ({}) - {}"));
      }
   }

   void handle_ready_to_write(file_writer &writer)
   {
      assert(nullptr != writer.m_fileDescriptor);
      if (false == writer.m_fileDescriptor->busy)
      {
         assert(false == writer.m_fileDescriptor->closeOnCompletion);
         write(writer);
      }
   }

   void handle_thread_task(thread_task &task)
   {
      assert(task.routine);
      task.routine();
      task.completionPromise.set_value();
   }

   void handle_write_completion(file_writer &writer)
   {
      assert(nullptr != writer.m_fileDescriptor);
      auto &fileDescriptor{*writer.m_fileDescriptor};
      fileDescriptor.busy = false;
      DWORD bytesTransferred{0};
      if (
         TRUE == GetOverlappedResult(
            fileDescriptor.handle,
            std::addressof(fileDescriptor.overlapped),
            std::addressof(bytesTransferred),
            FALSE
         )
      ) [[likely]]
      {
         write(writer);
      }
      else
      {
         /// Not enough space or something similar
         auto const errorCode{check_winapi_error("[file_writer] failed to write data to file: ({}) - {}")};
         close_file(writer);
         writer.io_closed(errorCode);
      }
   }

   [[nodiscard]] size_t poll(DWORD const timeout)
   {
      auto const numberOfCompletionPortEntriesRemoved
      {
         m_completionPort.get_queued_completion_statuses(
            *m_completionPortEntries,
            timeout
         )
      };
      assert(numberOfCompletionPortEntriesRemoved <= m_completionPortEntries->size());
      auto completionPortEntry{m_completionPortEntries->begin()};
      for (
         auto const completionPortEntriesEnd{completionPortEntry + numberOfCompletionPortEntriesRemoved};
         completionPortEntriesEnd != completionPortEntry;
         ++completionPortEntry
      )
      {
         handle_completion_port_entry(*completionPortEntry);
      }
      return numberOfCompletionPortEntriesRemoved;
   }

   void write(file_writer &writer)
   {
      assert(nullptr != writer.m_fileDescriptor);
      auto &fileDescriptor{*writer.m_fileDescriptor};
      assert(false == fileDescriptor.busy);
      auto const dataChunk{writer.io_ready_to_write()};
      if (0 == dataChunk.bytesLength)
      {
         if (true == fileDescriptor.closeOnCompletion)
         {
            close_file(writer);
            writer.io_closed(std::error_code{});
         }
         return;
      }
      fileDescriptor.busy = true;
      DWORD numberOfBytesWritten{0};
      if (
         FALSE == WriteFile(
            fileDescriptor.handle,
            dataChunk.bytes,
            static_cast<DWORD>(dataChunk.bytesLength),
            std::addressof(numberOfBytesWritten),
            std::addressof(fileDescriptor.overlapped)
         )
      ) [[likely]]
      {
         if (
            auto const errorCode
            {
               check_winapi_error_if_not("[file_writer] failed to write data to file: ({}) - {}", ERROR_IO_PENDING)
            };
            true == bool{errorCode}
         ) [[unlikely]]
         {
            fileDescriptor.busy = false;
            close_file(writer);
            writer.io_closed(errorCode);
         }
      }
   }

   [[nodiscard]] static DWORD file_writer_option_to_creation_disposition(
      file_writer_option const value,
      std::source_location const sourceLocation = std::source_location::current()
   )
   {
      switch (value)
      {
         case file_writer_option::create_new: return CREATE_NEW;
         case file_writer_option::create_or_open_and_truncate: return CREATE_ALWAYS;
         case file_writer_option::create_or_open_for_append: return OPEN_ALWAYS;
      }
      log_error(
         sourceLocation,
         "[file_writer] unexpected option {}: it must be a bug",
         to_underlying(value)
      );
      unreachable();
   }
};

}
