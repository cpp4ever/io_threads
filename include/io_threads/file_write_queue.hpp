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

#include "io_threads/data_chunk.hpp" ///< for io_threads::data_chunk
#include "io_threads/file_writer.hpp" ///< for io_threads::file_writer
#include "io_threads/file_writer_thread.hpp" ///< for io_threads::file_writer_thread

#include <atomic> ///< for std::atomic_bool, std::memory_order_acquire, std::memory_order_relaxed, std::memory_order_release
#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <cstddef> ///< for size_t
#include <memory> ///< for std::addressof, std::allocator, std::construct_at, std::destroy_at
#include <mutex> ///< for std::mutex, std::scoped_lock
#include <new> ///< for std::launder
#include <system_error> ///< for std::error_code
#include <type_traits> ///< for std::is_constructible_v, std::is_nothrow_constructible_v, std::is_pointer_v, std::is_reference_v
#include <utility> ///< for std::forward, std::move

namespace io_threads
{

template<typename type>
   requires((false == std::is_pointer_v<type>) && (false == std::is_reference_v<type>))
struct file_write_task final
{
   file_write_task *next{nullptr,};
   type value;

   file_write_task() = delete;
   file_write_task(file_write_task &&) = delete;
   file_write_task(file_write_task const &) = delete;

   template<typename ...types>
      requires(true == std::is_constructible_v<type, types...>)
   [[nodiscard]] file_write_task(types &&...values) noexcept(true == std::is_nothrow_constructible_v<type, types...>) :
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

   template<typename ...types>
      requires(true == std::is_constructible_v<type, types...>)
   [[maybe_unused, nodiscard]] file_write_task<type> &allocate(types &&...values)
   {
      return *std::launder(std::construct_at<file_write_task<type>>(m_allocator.allocate(1), std::forward<types>(values)...));
   }

   [[maybe_unused]] void deallocate(file_write_task<type> &task)
   {
      std::destroy_at(std::addressof(task));
      m_allocator.deallocate(std::addressof(task), 1);
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

   [[nodiscard]] explicit file_write_queue(file_writer_thread fileWriterThread) :
      super{std::move(fileWriterThread),},
      m_taskAllocator{},
      m_typeSerializer{}
   {}

   template<typename other_type_serializer>
   [[nodiscard]] file_write_queue(file_writer_thread fileWriterThread, other_type_serializer &&typeSerializer) :
      super{std::move(fileWriterThread),},
      m_taskAllocator{},
      m_typeSerializer{std::forward<other_type_serializer>(typeSerializer)}
   {}

   template<typename other_type_serializer, typename other_task_allocator>
   [[nodiscard]] file_write_queue(
      file_writer_thread fileWriterThread,
      other_type_serializer &&typeSerializer,
      other_task_allocator &&taskAllocator
   ) :
      super{std::move(fileWriterThread),},
      m_taskAllocator{std::forward<other_task_allocator>(taskAllocator)},
      m_typeSerializer{std::forward<other_type_serializer>(typeSerializer)}
   {}

   ~file_write_queue() override
   {
      assert(false == m_opened.load(std::memory_order_acquire));
   }

   file_write_queue &operator = (file_write_queue &&) = delete;
   file_write_queue &operator = (file_write_queue const &) = delete;

   template<typename ...types>
      requires(true == std::is_constructible_v<type, types...>)
   [[maybe_unused]] void push(types &&...values)
   {
      if (
         auto const wakeupIo{push_unordered_task(m_taskAllocator.allocate(std::forward<types>(values)...)),};
         (true == wakeupIo) && (true == m_opened.load(std::memory_order_relaxed))
      )
      {
         ready_to_write();
      }
   }

   template<typename forward_iterator, typename iterator>
   [[maybe_unused]] void push_batch(forward_iterator first, iterator const last)
   {
      if (last != first)
      {
         file_write_task<type> &firstTask{m_taskAllocator.allocate(*first),};
         auto *lastTask{std::addressof(firstTask),};
         for (++first; last != first; ++first)
         {
            lastTask->next = std::addressof(m_taskAllocator.allocate(*first));
            lastTask = lastTask->next;
         }
         if (auto const wakeupIo{push_unordered_task(firstTask),}; (true == wakeupIo) && (true == m_opened.load(std::memory_order_relaxed)))
         {
            ready_to_write();
         }
      }
   }

protected:
   void io_closed([[maybe_unused]] std::error_code const &errorCode) override
   {
      assert(
         false
         || (true == (bool{errorCode,}))
         || (false == m_opened.load(std::memory_order_acquire))
         || (false == io_has_tasks())
      );
      auto *tasks{std::launder(m_orderedTasks),};
      m_orderedTasks = nullptr;
      do
      {
         while (nullptr != tasks)
         {
            auto *task{std::launder(tasks),};
            tasks = std::launder(task->next);
            task->next = nullptr;
            m_taskAllocator.deallocate(*task);
         }
         tasks = pop_unordered_tasks();
      } while (nullptr != tasks);
      m_lastTaskOffset = 0;
      m_opened.store(false, std::memory_order_release);
   }

   void io_opened() override
   {
      m_opened.store(true, std::memory_order_release);
   }

private:
   std::atomic_bool m_opened{false,};
   file_write_task<type> *m_unorderedTasks{nullptr,};
   std::mutex m_tasksLock{};
   task_allocator m_taskAllocator;
   file_write_task<type> *m_orderedTasks{nullptr,};
   size_t m_lastTaskOffset{0,};
   type_serializer m_typeSerializer;

   [[maybe_unused, nodiscard]] bool io_has_tasks()
   {
      if (nullptr == m_orderedTasks)
      {
         [[maybe_unused]] std::scoped_lock const tasksGuard{m_tasksLock,};
         return nullptr != m_unorderedTasks;
      }
      return true;
   }

   [[nodiscard]] size_t io_ready_to_write(data_chunk const &dataChunk) final
   {
      m_typeSerializer.reset(dataChunk);
      size_t iteration{0,};
      do
      {
         while ((nullptr != m_orderedTasks) && (true == m_typeSerializer.update(m_orderedTasks->value, m_lastTaskOffset)))
         {
            auto *task{std::launder(m_orderedTasks),};
            m_orderedTasks = std::launder(task->next);
            task->next = nullptr;
            m_taskAllocator.deallocate(*task);
            m_lastTaskOffset = 0;
         }
         if ((nullptr != m_orderedTasks) || (0 != m_lastTaskOffset))
         {
            break;
         }
         auto *unorderedTasks{pop_unordered_tasks(),};
         while (nullptr != unorderedTasks)
         {
            auto *task{std::launder(unorderedTasks),};
            unorderedTasks = std::launder(task->next);
            task->next = std::launder(m_orderedTasks);
            m_orderedTasks = std::launder(task);
         }
      } while ((nullptr != m_orderedTasks) && (0 == iteration++));
      auto const bytesWritten{m_typeSerializer.finish(),};
      assert((0 < bytesWritten) || (nullptr == m_orderedTasks));
      return bytesWritten;
   }

   [[nodiscard]] file_write_task<type> *pop_unordered_tasks()
   {
      [[maybe_unused]] std::scoped_lock const tasksGuard{m_tasksLock,};
      auto *unorderedTasks{std::launder(m_unorderedTasks),};
      m_unorderedTasks = nullptr;
      return unorderedTasks;
   }

   [[nodiscard]] bool push_unordered_task(file_write_task<type> &task)
   {
      auto *lastTask{std::addressof(task),};
      for (; nullptr != lastTask->next; lastTask = lastTask->next)
      {
         continue;
      }
      [[maybe_unused]] std::scoped_lock const tasksGuard{m_tasksLock,};
      bool wakeupIo{nullptr == m_unorderedTasks,};
      lastTask->next = std::launder(m_unorderedTasks);
      m_unorderedTasks = std::launder(std::addressof(task));
      return wakeupIo;
   }
};

}
