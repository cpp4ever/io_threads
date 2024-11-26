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

#include "common/logger.hpp" ///< for io_threads::log_error
#include "common/memory_pool.hpp" ///< for io_threads::memory_pool
#include "common/thread_task.hpp" ///< for io_threads::thread_task
#include "common/utility.hpp" ///< for io_threads::to_underlying, io_threads::unreachable
#include "io_threads/file_writer.hpp" ///< for io_threads::file_writer
#include "io_threads/file_writer_option.hpp" ///< for io_threads::file_writer_option
#include "linux/file_descriptor.hpp" ///< for io_threads::file_descriptor

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

#pragma once
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
         // m_completionPort.post_queued_completion_status(
         //    to_completion_key(ioTask),
         //    to_completion_overlapped(file_writer_command::execute)
         // );
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
         // m_completionPort.post_queued_completion_status(
         //    to_completion_key(writer),
         //    to_completion_overlapped(file_writer_command::ready_to_close)
         // );
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
         // m_completionPort.post_queued_completion_status(
         //    to_completion_key(writer),
         //    to_completion_overlapped(file_writer_command::ready_to_open)
         // );
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
         // m_completionPort.post_queued_completion_status(
         //    to_completion_key(writer),
         //    to_completion_overlapped(file_writer_command::ready_to_write)
         // );
      }
   }

   void stop()
   {
      // m_completionPort.post_queued_completion_status(0, to_completion_overlapped(file_writer_command::unknown));
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
            (void)coreCpuId;
            file_writer_thread_worker worker{initialCapacityOfFileDescriptorList};
            workerPromise.set_value(worker);
            while (false == stopToken.stop_requested()) [[likely]]
            {
               // auto timeoutMilliseconds{completion_port::infinite_timeout};
               // while (worker.m_completionPortEntries->size() == worker.poll(timeoutMilliseconds))
               // {
               //    /// Do while there are entries to poll
               //    timeoutMilliseconds = completion_port::no_timeout;
               // }
            }
            // while (0 != worker.poll(completion_port::no_timeout))
            // {
            //    /// Until all entries are polled
            // }
         }
      };
   }

private:
   std::jthread::id const m_threadId{std::this_thread::get_id()};
   std::unique_ptr<memory_pool> const m_fileMemory;

   [[nodiscard]] explicit file_writer_thread_worker(size_t const initialCapacityOfFileDescriptorList) :
      m_fileMemory
      {
         std::make_unique<memory_pool>(
            initialCapacityOfFileDescriptorList,
            std::align_val_t{alignof(file_descriptor)},
            sizeof(file_descriptor)
         )
      }
   {}

   ~file_writer_thread_worker()
   {
   }

   void close_file(file_writer &writer)
   {
      (void)writer;
   }

   void handle_ready_to_close(file_writer &writer)
   {
      (void)writer;
   }

   void handle_ready_to_open(file_writer &writer)
   {
      (void)writer;
   }

   void handle_ready_to_write(file_writer &writer)
   {
      (void)writer;
   }

   void handle_thread_task(thread_task &task)
   {
      assert(task.routine);
      task.routine();
      task.completionPromise.set_value();
   }

   void handle_write_completion(file_writer &writer)
   {
      (void)writer;
   }

   void write(file_writer &writer)
   {
      (void)writer;
   }
};

}
