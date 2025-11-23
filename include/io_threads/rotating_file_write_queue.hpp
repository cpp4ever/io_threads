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
#include "io_threads/file_writer_config.hpp" ///< for io_threads::file_writer_config
#include "io_threads/file_writer_thread.hpp" ///< for io_threads::file_writer_thread
#include "io_threads/time.hpp" ///< for io_threads::system_time

#include <cassert> ///< for assert
#include <chrono> ///< for std::chrono::days, std::chrono::floor
#include <cstddef> ///< for size_t
#include <cstdint> ///< for uint8_t
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
struct rotating_file_write_task final
{
   rotating_file_write_task *next{nullptr,};
   system_time timestamp{};
   type value;

   rotating_file_write_task() = delete;
   rotating_file_write_task(rotating_file_write_task &&) = delete;
   rotating_file_write_task(rotating_file_write_task const &) = delete;

   template<typename ...types>
      requires(true == std::is_constructible_v<type, types...>)
   [[nodiscard]] rotating_file_write_task(types &&...values) noexcept(true == std::is_nothrow_constructible_v<type, types...>) :
      value{std::forward<types>(values)...}
   {}

   rotating_file_write_task &operator = (rotating_file_write_task &&) = delete;
   rotating_file_write_task &operator = (rotating_file_write_task const &) = delete;
};

template<typename type>
class [[maybe_unused]] rotating_file_write_task_allocator final
{
public:
   [[maybe_unused, nodiscard]] rotating_file_write_task_allocator() noexcept = default;
   [[maybe_unused, nodiscard]] rotating_file_write_task_allocator(rotating_file_write_task_allocator &&rhs) noexcept = default;
   [[maybe_unused, nodiscard]] rotating_file_write_task_allocator(rotating_file_write_task_allocator const &rhs) noexcept = default;

   [[maybe_unused]] rotating_file_write_task_allocator &operator = (rotating_file_write_task_allocator &&rhs) noexcept = default;
   [[maybe_unused]] rotating_file_write_task_allocator &operator = (rotating_file_write_task_allocator const &rhs) noexcept = default;

   template<typename ...types>
      requires(true == std::is_constructible_v<type, types...>)
   [[maybe_unused, nodiscard]] rotating_file_write_task<type> &allocate(types &&...values)
   {
      return *std::launder(std::construct_at<rotating_file_write_task<type>>(m_allocator.allocate(1), std::forward<types>(values)...));
   }

   [[maybe_unused]] void deallocate(rotating_file_write_task<type> &task)
   {
      std::destroy_at(std::addressof(task));
      m_allocator.deallocate(std::addressof(task), 1);
   }

private:
   std::allocator<rotating_file_write_task<type>> m_allocator{};
};

template<
   typename type,
   typename type_serializer,
   typename task_allocator = rotating_file_write_task_allocator<type>
>
class rotating_file_write_queue : public file_writer
{
private:
   using super = file_writer;

   enum struct status : uint8_t
   {
      idle,
      opening,
      ready,
      busy,
      closing,
   };

public:
   rotating_file_write_queue() = delete;
   rotating_file_write_queue(rotating_file_write_queue &&) = delete;
   rotating_file_write_queue(rotating_file_write_queue const &) = delete;

   [[nodiscard]] explicit rotating_file_write_queue(file_writer_thread fileWriterThread) :
      super{std::move(fileWriterThread),},
      m_taskAllocator{},
      m_typeSerializer{}
   {}

   template<typename other_type_serializer>
   [[nodiscard]] rotating_file_write_queue(file_writer_thread fileWriterThread, other_type_serializer &&typeSerializer) :
      super{std::move(fileWriterThread),},
      m_taskAllocator{},
      m_typeSerializer{std::forward<other_type_serializer>(typeSerializer)}
   {}

   template<typename other_type_serializer, typename other_task_allocator>
   [[nodiscard]] rotating_file_write_queue(
      file_writer_thread fileWriterThread,
      other_type_serializer &&typeSerializer,
      other_task_allocator &&taskAllocator
   ) :
      super{std::move(fileWriterThread),},
      m_taskAllocator{std::forward<other_task_allocator>(taskAllocator)},
      m_typeSerializer{std::forward<other_type_serializer>(typeSerializer)}
   {}

   ~rotating_file_write_queue() override
   {
      [[maybe_unused]] std::scoped_lock const tasksGuard{m_tasksLock,};
      assert(status::idle == m_status);
   }

   rotating_file_write_queue &operator = (rotating_file_write_queue &&) = delete;
   rotating_file_write_queue &operator = (rotating_file_write_queue const &) = delete;

   template<typename ...types>
      requires(true == std::is_constructible_v<type, types...>)
   void push(types &&...values)
   {
      auto &task{m_taskAllocator.allocate(std::forward<types>(values)...),};
      task.timestamp = get_timestamp(task.value);
      [[maybe_unused]] std::scoped_lock const tasksGuard{m_tasksLock,};
      task.next = std::launder(m_unorderedTasks);
      m_unorderedTasks = std::launder(std::addressof(task));
      if (status::ready == m_status)
      {
         assert(std::chrono::days::zero() != m_currentDay);
         m_status = status::busy;
         ready_to_write();
      }
      else if (status::idle == m_status) [[unlikely]]
      {
         assert(std::chrono::days::zero() == m_currentDay);
         m_status = status::opening;
         ready_to_open();
         io_queue_started();
      }
   }

   void stop()
   {
      [[maybe_unused]] std::scoped_lock const tasksGuard{m_tasksLock,};
      if (status::idle != m_status)
      {
         m_stopRequested = true;
         if (status::ready == m_status)
         {
            ready_to_close();
         }
      }
      else
      {
         io_queue_stopped(std::error_code{});
      }
   }

private:
   status m_status{status::idle,};
   bool m_stopRequested{false,};
   std::chrono::days m_currentDay{std::chrono::days::zero(),};
   rotating_file_write_task<type> *m_unorderedTasks{nullptr,};
   std::mutex m_tasksLock{};
   task_allocator m_taskAllocator;
   rotating_file_write_task<type> *m_orderedTasks{nullptr,};
   size_t m_lastTaskOffset{0,};
   type_serializer m_typeSerializer;

   [[nodiscard]] virtual system_time get_timestamp(type const &value) = 0;

   void io_closed(std::error_code const &errorCode) final
   {
      if (false == bool{errorCode,})
      {
         assert(0 == m_lastTaskOffset);
         [[maybe_unused]] std::scoped_lock const tasksGuard{m_tasksLock,};
         if (status::closing == m_status)
         {
            m_status = status::opening;
            ready_to_open();
            return;
         }
         assert(status::ready == m_status);
         assert(nullptr == m_orderedTasks);
         assert(nullptr == m_unorderedTasks);
      }
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
         [[maybe_unused]] std::scoped_lock const tasksGuard{m_tasksLock,};
         m_status = status::idle;
         assert((true == bool{errorCode,}) || (true == m_stopRequested));
         m_stopRequested = false;
         m_currentDay = std::chrono::days::zero();
         tasks = std::launder(m_unorderedTasks);
         m_unorderedTasks = nullptr;
      } while (nullptr != tasks);
      m_lastTaskOffset = 0;
      io_queue_stopped(errorCode);
   }

   void io_opened() final
   {
      assert(0 == m_lastTaskOffset);
      [[maybe_unused]] std::scoped_lock const tasksGuard{m_tasksLock,};
      assert(status::opening == m_status);
      assert(nullptr != m_orderedTasks);
      m_status = status::busy;
      m_currentDay = std::chrono::floor<std::chrono::days>(m_orderedTasks->timestamp).time_since_epoch();
   }

   virtual void io_queue_started() = 0;
   virtual void io_queue_stopped(std::error_code const &errorCode) = 0;

   [[nodiscard]] file_writer_config io_ready_to_open() final
   {
      [[maybe_unused]] std::scoped_lock const tasksGuard{m_tasksLock,};
      assert(status::opening == m_status);
      if (nullptr == m_orderedTasks)
      {
         update_ordered_tasks();
         assert(nullptr != m_orderedTasks);
      }
      return make_config(m_orderedTasks->timestamp);
   }

   [[nodiscard]] size_t io_ready_to_write(data_chunk const &dataChunk) final
   {
      m_typeSerializer.reset(dataChunk);
      size_t iteration{0,};
      do
      {
         while (nullptr != m_orderedTasks)
         {
            if (std::chrono::floor<std::chrono::days>(m_orderedTasks->timestamp).time_since_epoch() > m_currentDay) [[unlikely]]
            {
               assert(0 == m_lastTaskOffset);
               if (auto const bytesWritten{m_typeSerializer.finish(),}; 0 < bytesWritten)
               {
                  return bytesWritten;
               }
               [[maybe_unused]] std::scoped_lock const tasksGuard{m_tasksLock,};
               if (status::busy == m_status)
               {
                  m_status = status::closing;
                  ready_to_close();
               }
               else
               {
                  assert(status::closing == m_status);
               }
               return 0;
            }
            if (false == m_typeSerializer.update(m_orderedTasks->value, m_lastTaskOffset))
            {
               break;
            }
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
         [[maybe_unused]] std::scoped_lock const tasksGuard{m_tasksLock,};
         update_ordered_tasks();
      } while ((nullptr != m_orderedTasks) && (0 == iteration++));
      auto const bytesWritten{m_typeSerializer.finish(),};
      assert((0 < bytesWritten) || (nullptr == m_orderedTasks));
      return bytesWritten;
   }

   [[nodiscard]] virtual file_writer_config make_config(system_time timestamp) = 0;

   using super::ready_to_close;
   using super::ready_to_open;
   using super::ready_to_write;

   void update_ordered_tasks()
   {
      assert(nullptr == m_orderedTasks);
      assert(0 == m_lastTaskOffset);
      if (auto *unorderedTasks{std::launder(m_unorderedTasks),}; nullptr != unorderedTasks)
      {
         m_unorderedTasks = nullptr;
         while (nullptr != unorderedTasks)
         {
            auto *task{std::launder(unorderedTasks),};
            unorderedTasks = std::launder(task->next);
            task->next = std::launder(m_orderedTasks);
            m_orderedTasks = std::launder(task);
         }
      }
      else if (status::busy == m_status)
      {
         m_status = status::ready;
         if (true == m_stopRequested)
         {
            ready_to_close();
         }
      }
   }
};

}
