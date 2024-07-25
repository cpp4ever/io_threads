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
#include "common/object_pool.hpp" ///< for io_threads::object_pool
#include "common/utility.hpp" ///< for io_threads::to_underlying, io_threads::unreachable
#include "io_threads/file_writer.hpp" ///< for io_threads::file_writer_thread::file_writer
#include "io_threads/file_writer_option.hpp" ///< for io_threads::file_writer_option
#include "windows/completion_port.hpp" ///< for io_threads::completion_port, io_threads::from_completion_key, io_threads::to_completion_key
#include "windows/file_descriptor.hpp" ///< for io_threads::file_descriptor
#include "windows/file_writer_command.hpp" ///< for io_threads::file_writer_command, io_threads::from_completion_overlapped
#include "windows/winapi_error.hpp" ///< for io_threads::check_winapi_error, io_threads::check_winapi_error_if_not

/// for
///   CloseHandle,
///   CREATE_ALWAYS,
///   CREATE_NEW,
///   CreateFileW,
///   DWORD,
///   ERROR_IO_PENDING,
///   FALSE,
///   FILE_ATTRIBUTE_NORMAL,
///   FILE_FLAG_OVERLAPPED,
///   FILE_SHARE_READ,
///   FILE_WRITE_DATA,
///   FlushFileBuffers,
///   GetOverlappedResult,
///   HANDLE,
///   INVALID_HANDLE_VALUE,
///   MAXDWORD,
///   OPEN_ALWAYS,
///   OVERLAPPED_ENTRY,
///   TRUE,
///   WriteFile
#include <Windows.h>

#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <cstddef> ///< for size_t
#include <future> ///< for std::promise
#include <memory> ///< for std::addressof
#include <new> ///< for std::align_val_t
#include <source_location> ///< for std::source_location
#include <stop_token> ///< for std::stop_token
#include <system_error> ///< for std::error_code

#pragma comment(lib, "kernel32.lib")

namespace io_threads
{

class file_writer::file_writer_thread_worker final
{
public:
   file_writer_thread_worker() = delete;
   file_writer_thread_worker(file_writer_thread_worker &&) = delete;
   file_writer_thread_worker(file_writer_thread_worker const &) = delete;

   [[nodiscard]] file_writer_thread_worker(
      size_t const initialCapacityOfFileDescriptorList,
      std::promise<completion_port const &> &completionPortPromise
   ) :
      m_fileDescriptors{initialCapacityOfFileDescriptorList}
   {
      completionPortPromise.set_value(m_completionPort);
   }

   file_writer_thread_worker &operator = (file_writer_thread_worker &&) = delete;
   file_writer_thread_worker &operator = (file_writer_thread_worker const &) = delete;

   void run(std::stop_token const stopToken)
   {
      while (false == stopToken.stop_requested()) [[likely]]
      {
         auto timeoutMilliseconds = completion_port::infinite_timeout;
         while (m_completionPortEntries.size() == poll(timeoutMilliseconds))
         {
            /// Do while there are entries to poll
            timeoutMilliseconds = completion_port::no_timeout;
         }
      }
      while (0 != poll(completion_port::no_timeout))
      {
         /// Until all entries are polled
      }
   }

private:
   completion_port m_completionPort = {};
   completion_port::entries m_completionPortEntries = {};
   object_pool<file_descriptor> m_fileDescriptors;

   void close_file(file_writer &writer)
   {
      assert(nullptr != writer.m_fileDescriptor);
      auto &fileDescriptor = *writer.m_fileDescriptor;
      assert(false == fileDescriptor.busy);
      if (FALSE == FlushFileBuffers(fileDescriptor.handle)) [[unlikely]]
      {
         check_winapi_error("[file_writer] failed to flush file buffers: ({}) - {}");
      }
      if (FALSE == CloseHandle(fileDescriptor.handle)) [[unlikely]]
      {
         check_winapi_error("[file_writer] failed to close file: ({}) - {}");
      }
      m_fileDescriptors.push(fileDescriptor);
      writer.m_fileDescriptor = nullptr;
   }

   void handle_completion_port_entry(OVERLAPPED_ENTRY const &completionPortEntry)
   {
      auto *writer = from_completion_key<file_writer>(completionPortEntry.lpCompletionKey);
      switch (from_completion_overlapped(completionPortEntry.lpOverlapped))
      {
      case file_writer_command::unknown:
      {
         /// Generated by dtor of io_threads::file_writer_thread::file_writer_thread_impl
         assert(nullptr == writer);
      }
      break;

      case file_writer_command::ready_to_open:
      {
         assert(nullptr != writer);
         handle_ready_to_open(*writer);
      }
      break;

      case file_writer_command::ready_to_write:
      {
         assert(nullptr != writer);
         handle_ready_to_write(*writer);
      }
      break;

      case file_writer_command::ready_to_close:
      {
         assert(nullptr != writer);
         handle_ready_to_close(*writer);
      }
      break;

      default:
      {
         /// Generated by WriteFile
         assert(nullptr != writer);
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
      close_file(writer);
      writer.io_closed(std::error_code{});
   }

   void handle_ready_to_open(file_writer &writer)
   {
      assert(nullptr == writer.m_fileDescriptor);
      auto const config = writer.io_ready_to_open();
      auto const fileHandle = CreateFileW(
         config.path().c_str(),
         FILE_WRITE_DATA,
         FILE_SHARE_READ,
         nullptr,
         file_writer_option_to_creation_disposition(config.option()),
         FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
         nullptr
      );
      if (INVALID_HANDLE_VALUE != fileHandle) [[likely]]
      {
         m_completionPort.add_handle(fileHandle, to_completion_key(writer));
         auto &fileDescriptor = m_fileDescriptors.pop();
         assert(INVALID_HANDLE_VALUE == fileDescriptor.handle);
         assert(false == fileDescriptor.busy);
         fileDescriptor.handle = fileHandle;
         fileDescriptor.overlapped.Offset = fileDescriptor.overlapped.OffsetHigh = MAXDWORD;
         writer.m_fileDescriptor = std::addressof(fileDescriptor);
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
         write(writer);
      }
   }

   void handle_write_completion(file_writer &writer)
   {
      assert(nullptr != writer.m_fileDescriptor);
      auto &fileDescriptor = *writer.m_fileDescriptor;
      fileDescriptor.busy = false;
      DWORD bytesTransferred = 0;
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
         auto const errorCode = check_winapi_error("[file_writer] failed to write data to file: ({}) - {}");
         close_file(writer);
         writer.io_closed(errorCode);
      }
   }

   [[nodiscard]] size_t poll(DWORD const timeout)
   {
      auto const numberOfCompletionPortEntriesRemoved = m_completionPort.get_queued_completion_statuses(m_completionPortEntries, timeout);
      assert(numberOfCompletionPortEntriesRemoved <= m_completionPortEntries.size());
      auto completionPortEntry = m_completionPortEntries.begin();
      for (
         auto const completionPortEntriesEnd = completionPortEntry + numberOfCompletionPortEntriesRemoved;
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
      auto &fileDescriptor = *writer.m_fileDescriptor;
      assert(false == fileDescriptor.busy);
      auto const dataChunk = writer.io_ready_to_write();
      if (0 == dataChunk.bytesLength)
      {
         return;
      }
      fileDescriptor.busy = true;
      DWORD numberOfBytesWritten = 0;
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
            auto const errorCode = check_winapi_error_if_not("[file_writer] failed to write data to file: ({}) - {}", ERROR_IO_PENDING);
            errorCode
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
