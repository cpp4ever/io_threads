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

#pragma once

#include "common/utility.hpp" ///< for io_threads::unreachable
#include "windows/winapi_error.hpp" ///< for io_threads::check_winapi_error, io_threads::check_winapi_error_if_not

/// for
///   BOOL,
///   CloseHandle,
///   CreateIoCompletionPort,
///   DWORD,
///   FALSE,
///   FillMemory,
///   GetQueuedCompletionStatusEx,
///   HANDLE,
///   INFINITE,
///   INVALID_HANDLE_VALUE,
///   LPOVERLAPPED,
///   OVERLAPPED_ENTRY,
///   PostQueuedCompletionStatus,
///   TRUE,
///   ULONG,
///   ULONG_PTR,
///   WAIT_TIMEOUT
#include <Windows.h>

#include <array> ///< for std::array
#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <memory> ///< for std::addressof

#pragma comment(lib, "kernel32")

namespace io_threads
{

class completion_port final
{
private:
   static constexpr BOOL alertable_wait{FALSE};
   static constexpr ULONG completion_port_entries_count{1024 / sizeof(OVERLAPPED_ENTRY)};
   static constexpr DWORD number_of_concurrent_threads{1};
   static constexpr DWORD unknown_number_of_bytes_transferred{0};

public:
   using entries = std::array<OVERLAPPED_ENTRY, completion_port_entries_count>;
   static constexpr DWORD infinite_timeout{INFINITE};
   static constexpr DWORD no_timeout{0};

   [[nodiscard]] completion_port() :
      m_completionPort
      {
         CreateIoCompletionPort(
            INVALID_HANDLE_VALUE, ///< FileHandle
            nullptr, ///< ExistingCompletionPort
            0, ///< CompletionKey
            number_of_concurrent_threads
         )
      }
   {
      if (nullptr == m_completionPort) [[unlikely]]
      {
         check_winapi_error("[io_threads] failed to create input/output completion port: ({}) - {}");
         unreachable();
      }
   }

   completion_port(completion_port &&) = delete;
   completion_port(completion_port const &) = delete;

   ~completion_port()
   {
      assert(nullptr != m_completionPort);
      if (FALSE == CloseHandle(m_completionPort)) [[unlikely]]
      {
         check_winapi_error("[io_threads] failed to close input/output completion port: ({}) - {}");
      }
   }

   completion_port &operator = (completion_port &&) = delete;
   completion_port &operator = (completion_port const &) = delete;

   void add_handle(HANDLE const fileHandleOrSocket, ULONG_PTR const completionKey) const
   {
      assert(nullptr != m_completionPort);
      assert(INVALID_HANDLE_VALUE != fileHandleOrSocket);
      assert(0 != completionKey);
      if (
         m_completionPort == CreateIoCompletionPort(
            fileHandleOrSocket,
            m_completionPort,
            completionKey,
            number_of_concurrent_threads
         )
      ) [[likely]]
      {
         return;
      }
      check_winapi_error("[io_threads] failed to bind handle to input/output completion port: ({}) - {}");
      unreachable();
   }

   [[nodiscard]] ULONG get_queued_completion_statuses(entries &entries, DWORD const timeoutMilliseconds) const
   {
      assert(nullptr != m_completionPort);
      FillMemory(entries.data(), completion_port_entries_count * sizeof(OVERLAPPED_ENTRY), 0);
      ULONG numberOfEntriesRemoved{0};
      if (
         TRUE == GetQueuedCompletionStatusEx(
            m_completionPort,
            entries.data(),
            completion_port_entries_count,
            std::addressof(numberOfEntriesRemoved),
            timeoutMilliseconds,
            alertable_wait
         )
      ) [[likely]]
      {
         return numberOfEntriesRemoved;
      }
      if (
         auto const errorCode
         {
            check_winapi_error_if_not(
               "[io_threads] failed to get queued completion statuses: ({}) - {}",
               WAIT_TIMEOUT
            )
         };
         true == bool{errorCode}
      ) [[unlikely]]
      {
         unreachable();
      }
      return 0;
   }

   void post_queued_completion_status(ULONG_PTR const completionKey, LPOVERLAPPED const completionOverlapped) const
   {
      assert(nullptr != m_completionPort);
      if (
         TRUE == PostQueuedCompletionStatus(
            m_completionPort,
            unknown_number_of_bytes_transferred,
            completionKey,
            completionOverlapped
         )
      ) [[likely]]
      {
         return;
      }
      check_winapi_error("[io_threads] failed to post queued completion status: ({}) - {}");
      unreachable();
   }

private:
   HANDLE m_completionPort;
};

template<typename type>
[[nodiscard]] constexpr type *from_completion_key(ULONG_PTR const value)
{
   return std::bit_cast<type *>(value);
}

template<typename type>
[[nodiscard]] constexpr ULONG_PTR to_completion_key(type const &value)
{
   return std::bit_cast<ULONG_PTR const>(std::addressof(value));
}

}
