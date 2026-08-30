/*
   Part of the io_threads project (https://github.com/cpp4ever/io_threads), under the MIT License
   SPDX-License-Identifier: MIT

   Copyright (c) 2024-2026 Mikhail Smirnov

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
#include "common/utility.hpp" ///< for io_threads::unreachable

/// for
///   io_uring,
///   io_uring_get_sqe,
///   io_uring_prep_close_direct,
///   io_uring_prep_read_fixed,
///   io_uring_register_files_update,
///   io_uring_sqe
///   io_uring_sqe_set_data,
///   IOSQE_FIXED_FILE
#include <liburing.h>
#include <sys/eventfd.h> ///< for EFD_NONBLOCK, eventfd, eventfd_t, eventfd_write
#include <sys/uio.h> ///< for iovec
#include <unistd.h> ///< for close

#include <algorithm> ///< for std::ranges::any_of
#include <array> ///< for std::array
#include <cassert> ///< for assert
#include <cerrno> ///< for errno
#include <cstdint> ///< for uint32_t
#include <memory> ///< for std::addressof
#include <ranges> ///< for std::views::iota
#include <source_location> ///< for std::source_location
#include <span> ///< for std::span

namespace io_threads
{

[[nodiscard]] inline io_uring_sqe &submission_queue_entry(io_uring &ring, void *userdata)
{
   assert(nullptr != userdata);
   auto *submissionQueueEntry{io_uring_get_sqe(std::addressof(ring)),};
   if (nullptr == submissionQueueEntry) [[unlikely]]
   {
      log_error(std::source_location::current(), "[io_uring] failed to get submission queue entry, it must be a bug");
      unreachable();
   }
   io_uring_sqe_set_data(submissionQueueEntry, userdata);
   return *submissionQueueEntry;
}

class uring_alarm final
{
public:
   static constexpr inline auto number_of_alarms{2u,};

   struct client_tag
   {};

   struct thread_tag
   {};

   [[maybe_unused, nodiscard]] uring_alarm()
   {
      for (auto &handle : m_handles)
      {
         if (-1 == (handle = eventfd(0u, EFD_NONBLOCK))) [[unlikely]]
         {
            log_system_error("[os] failed to create an eventfd: ({}) - {}", errno);
            unreachable();
         }
      }
   }

   uring_alarm(uring_alarm &&) = delete;
   uring_alarm(uring_alarm const &) = delete;

   ~uring_alarm()
   {
      for (int const handle : m_handles)
      {
         assert(-1 != handle);
         if (-1 == close(handle)) [[unlikely]]
         {
            log_system_error("[os] failed to destroy the eventfd: ({}) - {}", errno);
         }
      }
   }

   uring_alarm &operator = (uring_alarm &&) = delete;
   uring_alarm &operator = (uring_alarm const &) = delete;

   [[nodiscard]] bool client_alarm(void *userdata) const noexcept
   {
      return std::addressof(m_handles.front()) == userdata;
   }

   [[nodiscard]] bool thread_alarm(void *userdata) const noexcept
   {
      return std::addressof(m_handles.back()) == userdata;
   }

   void register_buffers(std::span<iovec> buffers)
   {
      for (auto const alarmIndex : std::views::iota(0u, number_of_alarms))
      {
         buffers[alarmIndex] = iovec{.iov_base = std::addressof(m_values[alarmIndex]), .iov_len = sizeof(eventfd_t),};
      }
   }

   [[nodiscard]] uint32_t start(io_uring &ring)
   {
      assert(false == std::ranges::any_of(m_handles, [] (auto const handle) { return -1 == handle; }));
      if (
         auto const returnCode{io_uring_register_files_update(std::addressof(ring), 0u, m_handles.data(), number_of_alarms),};
         0 > returnCode
      ) [[unlikely]]
      {
         log_system_error("[io_uring] failed to update files: ({}) - {}", -returnCode);
         unreachable();
      }
      for (auto const alarmIndex : std::views::iota(0u, number_of_alarms))
      {
         set(ring, m_handles[alarmIndex], m_values[alarmIndex], alarmIndex);
      }
      return number_of_alarms;
   }

   [[nodiscard]] uint32_t stop(io_uring &ring)
   {
      for (auto const alarmIndex : std::views::iota(0u, number_of_alarms))
      {
         io_uring_prep_close_direct(std::addressof(submission_queue_entry(ring, std::addressof(m_handles[alarmIndex]))), alarmIndex);
      }
      return number_of_alarms;
   }

   [[nodiscard]] uint32_t set(io_uring &ring)
   {
      set(ring, m_handles.front(), m_values.front(), 0);
      return 1u;
   }

   void wake(client_tag const)
   {
      raise(m_handles.front());
   }

   void wake(thread_tag const)
   {
      raise(m_handles.back());
   }

private:
   std::array<int, number_of_alarms> m_handles{-1, -1,};
   std::array<eventfd_t, number_of_alarms> m_values{0u, 0u,};

   static void raise(int const handle)
   {
      assert(-1 != handle);
      if (-1 == eventfd_write(handle, 1u)) [[unlikely]]
      {
         log_system_error("[os] failed to write to the eventfd: ({}) - {}", errno);
         unreachable();
      }
   }

   static void set(io_uring &ring, int &handle, eventfd_t &value, int const bufferIndex)
   {
      auto &submissionQueueEntry{submission_queue_entry(ring, std::addressof(handle)),};
      io_uring_prep_read_fixed(
         std::addressof(submissionQueueEntry),
         bufferIndex,
         std::addressof(value),
         sizeof(eventfd_t),
         0,
         bufferIndex
      );
      submissionQueueEntry.flags |= IOSQE_FIXED_FILE;
   }
};

constexpr uring_alarm::client_tag uring_client_alarm{};
constexpr uring_alarm::thread_tag uring_thread_alarm{};

}
