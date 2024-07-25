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

#include <common/shared_memory_pool.hpp> ///< for io_threads::shared_memory_pool
#include <common/utility.hpp> ///< for io_threads::unreachable
#include <linux/uring_listener.hpp> ///< for io_threads::uring_listener

#include <errno.h> ///< for errno
#include <liburing.h> ///< for io_uring_prep_close, io_uring_prep_read, io_uring_sqe
#include <sys/eventfd.h> ///< for EFD_NONBLOCK, eventfd, eventfd_t, eventfd_write

#include <atomic> ///< for std::atomic, std::memory_order_acq_rel, std::memory_order_relaxed, std::memory_order_release
#include <cassert> ///< for assert
#include <cstddef> ///< for size_t
#include <cstdint> ///< for int32_t, intptr_t, uint32_t
#include <memory> ///< for std::addressof
#include <new> ///< for std::align_val_t, std::launder

namespace io_threads
{

class uring_command_queue final
{
private:
   struct queue_item final
   {
      queue_item *next{nullptr,};
      intptr_t commandId{0,};
      intptr_t commandTarget{0,};
   };

public:
   uring_command_queue() = delete;
   uring_command_queue(uring_command_queue &&) = delete;
   uring_command_queue(uring_command_queue const &) = delete;

   [[nodiscard]] explicit uring_command_queue(size_t const initialCapacityOfCommandQueue) :
      m_memoryPool{initialCapacityOfCommandQueue, std::align_val_t{alignof(queue_item)}, sizeof(queue_item)}
   {}

   uring_command_queue &operator = (uring_command_queue &&) = delete;
   uring_command_queue &operator = (uring_command_queue const &) = delete;

   void handle(uring_listener &uringListener)
   {
      queue_item *orderedItems{nullptr,};
      auto *unorderedItems{m_slistHead.exchange(nullptr, std::memory_order_acq_rel),};
      while (nullptr != unorderedItems)
      {
         auto *item{std::launder(unorderedItems),};
         unorderedItems = item->next;
         item->next = orderedItems;
         orderedItems = item;
      }
      while (nullptr != orderedItems)
      {
         auto *item{std::launder(orderedItems),};
         orderedItems = item->next;
         uringListener.handle_command(item->commandId, item->commandTarget);
         m_memoryPool.push_object(*item);
      }
   }

   void push(intptr_t const commandId, intptr_t const commandTarget)
   {
      auto &item
      {
         m_memoryPool.pop_object<queue_item>(
            queue_item
            {
               .next = m_slistHead.load(std::memory_order_relaxed),
               .commandId = commandId,
               .commandTarget = commandTarget,
            }
         ),
      };
      while (
         false == m_slistHead.compare_exchange_strong(
            item.next,
            std::addressof(item),
            std::memory_order_release,
            std::memory_order_relaxed
         )
      )
      {}
   }

private:
   shared_memory_pool m_memoryPool;
   std::atomic<queue_item *> m_slistHead{nullptr};
};

}
