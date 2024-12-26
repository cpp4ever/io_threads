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

#include "io_threads/data_chunk.hpp" ///< for io_threads::data_chunk
#include "io_threads/file_writer.hpp" ///< for io_threads::file_writer
#include "io_threads/file_writer_thread.hpp" ///< for io_threads::file_writer_thread

#include <atomic> ///< for std::atomic, std::atomic_bool, std::memory_order_acq_rel, std::memory_order_relaxed, std::memory_order_release
#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <cstddef> ///< for size_t
#include <memory> ///< for std::allocator, std::construct_at, std::destroy_at
#include <new> ///< for std::launder
#include <system_error> ///< for std::error_code
#include <type_traits> ///< for std::is_constructible_v
#include <utility> ///< for std::forward

namespace io_threads
{

template<typename type>
struct file_write_task final
{
   file_write_task *next{nullptr};
   type value;

   file_write_task() = delete;
   file_write_task(file_write_task &&) = delete;
   file_write_task(file_write_task const &) = delete;

   template<typename ...types>
   [[nodiscard]] file_write_task(file_write_task *nextTask, types &&...values) :
      next{nextTask},
      value{std::forward<types>(values)...}
   {}

   file_write_task &operator = (file_write_task &&) = delete;
   file_write_task &operator = (file_write_task const &) = delete;
};

template<typename type>
class [[maybe_unused]] file_write_task_allocator final
{
public:
   [[maybe_unused, nodiscard]] file_write_task_allocator() noexcept = default;
   [[maybe_unused, nodiscard]] file_write_task_allocator(file_write_task_allocator &&rhs) noexcept = default;
   [[maybe_unused, nodiscard]] file_write_task_allocator(file_write_task_allocator const &rhs) noexcept = default;

   [[maybe_unused]] file_write_task_allocator &operator = (file_write_task_allocator &&rhs) noexcept = default;
   [[maybe_unused]] file_write_task_allocator &operator = (file_write_task_allocator const &rhs) noexcept = default;

   [[maybe_unused, nodiscard]] file_write_task<type> *allocate()
   {
      return m_allocator.allocate(1);
   }

   [[maybe_unused]] void deallocate(file_write_task<type> *task)
   {
      m_allocator.deallocate(task, 1);
   }

private:
   std::allocator<file_write_task<type>> m_allocator{};
};

template<
   typename type,
   typename type_serializer,
   typename task_allocator = file_write_task_allocator<type>
>
class file_write_queue : public file_writer
{
private:
   using super = file_writer;

public:
   file_write_queue() = delete;
   file_write_queue(file_write_queue &&) = delete;
   file_write_queue(file_write_queue const &) = delete;

   [[nodiscard]] explicit file_write_queue(file_writer_thread const &fileWriterThread) :
      super{fileWriterThread},
      m_taskAllocator{},
      m_typeSerializer{}
   {}

   template<typename other_type_serializer>
   [[nodiscard]] file_write_queue(
      file_writer_thread const &fileWriterThread,
      other_type_serializer &&typeSerializer
   ) :
      super{fileWriterThread},
      m_taskAllocator{},
      m_typeSerializer{std::forward<other_type_serializer>(typeSerializer)}
   {}

   template<typename other_type_serializer, typename other_task_allocator>
   [[nodiscard]] file_write_queue(
      file_writer_thread const &fileWriterThread,
      other_type_serializer &&typeSerializer,
      other_task_allocator &&taskAllocator
   ) :
      super{fileWriterThread},
      m_taskAllocator{std::forward<other_task_allocator>(taskAllocator)},
      m_typeSerializer{std::forward<other_type_serializer>(typeSerializer)}
   {}

   ~file_write_queue() override
   {
      assert((nullptr == m_orderedTasks) && (nullptr == m_unorderedTasks.load(std::memory_order_relaxed)));
      reset();
   }

   file_write_queue &operator = (file_write_queue &&) = delete;
   file_write_queue &operator = (file_write_queue const &) = delete;

   template<typename ...types>
      requires(true == std::is_constructible_v<type, types...>)
   void push(types &&...values)
   {
      auto *task
      {
         std::launder(
            std::construct_at<file_write_task<type>>(
               std::bit_cast<file_write_task<type> *>(m_taskAllocator.allocate()),
               m_unorderedTasks.load(std::memory_order_relaxed),
               std::forward<types>(values)...
            )
         )
      };
      auto wakeUpIo{nullptr == task->next,};
      while (
         false == m_unorderedTasks.compare_exchange_strong(
            task->next,
            task,
            std::memory_order_release,
            std::memory_order_relaxed
         )
      )
      {}
      if ((true == wakeUpIo) && (true == m_open.load(std::memory_order_relaxed)))
      {
         ready_to_write();
      }
   }

protected:
   void io_closed([[maybe_unused]] std::error_code const &errorCode) override
   {
      assert(
         false
         || (true == bool{errorCode})
         || (
            true
            && (nullptr == m_orderedTasks)
            && (nullptr == m_unorderedTasks.load(std::memory_order_relaxed))
         )
      );
      reset();
   }

   void io_opened() override
   {
      m_open.store(true, std::memory_order_release);
   }

private:
   task_allocator m_taskAllocator;
   file_write_task<type> *m_orderedTasks{nullptr};
   type_serializer m_typeSerializer;
   std::atomic<file_write_task<type> *> m_unorderedTasks{nullptr};
   std::atomic_bool m_open{false};

   [[nodiscard]] data_chunk io_ready_to_write() final
   {
      m_typeSerializer.reset();
      size_t iteration{0};
      do
      {
         while ((nullptr != m_orderedTasks) && (true == m_typeSerializer.update(m_orderedTasks->value)))
         {
            auto *task{std::launder(m_orderedTasks)};
            m_orderedTasks = task->next;
            std::destroy_at(task);
            m_taskAllocator.deallocate(task);
         }
         if (nullptr != m_orderedTasks)
         {
            break;
         }
         auto *unorderedTasks{m_unorderedTasks.exchange(nullptr, std::memory_order_acq_rel)};
         while (nullptr != unorderedTasks)
         {
            auto *task{std::launder(unorderedTasks)};
            unorderedTasks = task->next;
            task->next = m_orderedTasks;
            m_orderedTasks = task;
         }
      } while ((nullptr != m_orderedTasks) && (0 == iteration++));
      auto const dataChunk{m_typeSerializer.finish()};
      assert((0 < dataChunk.bytesLength) || (nullptr == m_orderedTasks));
      return dataChunk;
   }

   void reset()
   {
      do
      {
         while (nullptr != m_orderedTasks)
         {
            auto *task{std::launder(m_orderedTasks)};
            m_orderedTasks = task->next;
            std::destroy_at(task);
            m_taskAllocator.deallocate(task);
         }
         m_orderedTasks = m_unorderedTasks.exchange(nullptr, std::memory_order_acq_rel);
      } while (nullptr != m_orderedTasks);
      m_open.store(false, std::memory_order_relaxed);
   }
};

}
