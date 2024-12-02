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

#include <common/logger.hpp> ///< for io_threads::log_error, io_threads::log_system_error
#include <common/utility.hpp> ///< for io_threads::unreachable
#include <linux/uring_command_queue.hpp> ///< for io_threads::uring_command_queue
#include <linux/uring_listener.hpp> ///< for io_threads::uring_listener

#include <errno.h> ///< for errno
/// for
///   io_uring,
///   io_uring_cq_advance,
///   io_uring_cqe,
///   io_uring_cqe_get_data,
///   io_uring_get_sqe,
///   io_uring_for_each_cqe,
///   io_uring_queue_exit,
///   io_uring_queue_init,
///   io_uring_register_files,
///   io_uring_sqe,
///   io_uring_sqe_set_data,
///   io_uring_sqe_set_flags,
///   io_uring_submit_and_wait_timeout,
///   io_uring_unregister_files,
///   IORING_SETUP_SINGLE_ISSUER
#include <liburing.h>
#include <signal.h> ///< for sigfillset, sigset_t

#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <cstddef> ///< for size_t
#include <cstdint> ///< for int32_t, intptr_t, uint32_t
#include <memory> ///< for std::addressof, std::make_unique, std::unique_ptr
#include <source_location> ///< for std::source_location
#include <stop_token> ///< for std::stop_token
#include <vector> ///< for std::vector

namespace io_threads
{

class uring_worker final
{
public:
   uring_worker() = delete;
   uring_worker(uring_worker &&) = delete;
   uring_worker(uring_worker const &) = delete;

   [[nodiscard]] explicit uring_worker(size_t const capacityOfDescriptorList, size_t const capacityOfRingQueue)
   {
      assert(0 < capacityOfRingQueue);
      assert(nullptr != m_ring);
      if (
         auto const returnCode{io_uring_queue_init(capacityOfRingQueue, m_ring.get(), IORING_SETUP_SINGLE_ISSUER),};
         0 > returnCode
      ) [[unlikely]]
      {
         log_system_error(std::source_location::current(), "[io_uring] failed to initialize the ring: ({}) - {}", -returnCode);
         unreachable();
      }
      if (-1 == sigfillset(m_sigmask.get())) [[unlikely]]
      {
         log_system_error(std::source_location::current(), "[io_uring] failed to initialize sigmask: ({}) - {}", errno);
         unreachable();
      }
      m_registeredDescriptors.resize(capacityOfDescriptorList, -1);
      if (
         auto const returnCode
         {
            io_uring_register_files(
               m_ring.get(),
               m_registeredDescriptors.data(),
               static_cast<uint32_t>(m_registeredDescriptors.size())
            ),
         };
         0 > returnCode
      ) [[unlikely]]
      {
         log_system_error(std::source_location::current(), "[io_uring] failed to register files: ({}) - {}", -returnCode);
         unreachable();
      }
   }

   ~uring_worker()
   {
      assert(nullptr != m_ring);
      if (auto const returnCode{io_uring_unregister_files(m_ring.get()),}; 0 > returnCode)
      {
         log_system_error(std::source_location::current(), "[io_uring] failed to unregister files: ({}) - {}", -returnCode);
      }
      io_uring_queue_exit(m_ring.get());
   }

   uring_worker &operator = (uring_worker &&) = delete;
   uring_worker &operator = (uring_worker const &) = delete;

   [[nodiscard]] io_uring_sqe &submission_entry(void *userdata)
   {
      assert(nullptr != userdata);
      assert(nullptr != m_ring);
      auto *submissionQueueEntry{io_uring_get_sqe(m_ring.get()),};
      if (nullptr == submissionQueueEntry) [[unlikely]]
      {
         log_error(std::source_location::current(), "[io_uring] failed to get submission queue entry");
         unreachable();
      }
      io_uring_sqe_set_data(submissionQueueEntry, userdata);
      return *submissionQueueEntry;
   }

   void run(std::stop_token const stopToken, uring_command_queue &uringCommandQueue, uring_listener &uringListener)
   {
      assert(nullptr != m_ring);
      uringCommandQueue.prep_read(submission_entry(this));
      for (auto stopping{false,}; false == stopping; )
      {
         io_uring_cqe *completionQueueEntry{nullptr,};
         if (
            auto const returnCode{io_uring_submit_and_wait_timeout(m_ring.get(), std::addressof(completionQueueEntry), 1, nullptr, m_sigmask.get()),};
            0 > returnCode
         ) [[unlikely]]
         {
            log_system_error(std::source_location::current(), "[io_uring] failed to submit prepared tasks: ({}) - {}", -returnCode);
            unreachable();
         }
         stopping = stopToken.stop_requested();
         uint32_t completionQueueHead;
         uint32_t numberOfCompletionQueueEntriesRemoved{0,};
         io_uring_for_each_cqe(m_ring.get(), completionQueueHead, completionQueueEntry)
         {
            auto *userdata{io_uring_cqe_get_data(completionQueueEntry),};
            assert(nullptr != userdata);
            if (this == userdata)
            {
               if (0 <= completionQueueEntry->res) [[likely]]
               {
                  if (false == stopping) [[likely]]
                  {
                     uringCommandQueue.prep_read(submission_entry(this));
                  }
                  uringCommandQueue.handle_read(uringListener, completionQueueEntry->res, completionQueueEntry->flags);
               }
               else
               {
                  assert(0 > completionQueueEntry->res);
                  log_system_error(std::source_location::current(), "[io_uring] failed to reset eventfd: ({}) - {}", errno);
                  unreachable();
               }
            }
            else
            {
               uringListener.handle_completion(std::bit_cast<intptr_t>(userdata), completionQueueEntry->res, completionQueueEntry->flags);
            }
            ++numberOfCompletionQueueEntriesRemoved;
         }
         io_uring_cq_advance(m_ring.get(), numberOfCompletionQueueEntriesRemoved);
         assert((false == stopping) || (1 == numberOfCompletionQueueEntriesRemoved));
      }
   }

private:
   std::unique_ptr<io_uring> m_ring{std::make_unique<io_uring>(),};
   std::unique_ptr<sigset_t> m_sigmask{std::make_unique<sigset_t>(),};
   std::vector<int32_t> m_registeredDescriptors{};
};

}
