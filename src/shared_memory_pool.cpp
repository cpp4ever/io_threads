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

#include "common/shared_memory_pool.hpp" ///< for io_threads::shared_memory_pool

#include <algorithm> ///< for std::max
#include <atomic> ///< for std::memory_order_relaxed, std::memory_order_release
#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <cstddef> ///< for size_t, std::byte
#include <cstring> ///< for std::memset
#include <memory> ///< for std::construct_at, std::destroy_at
#include <new> ///< for operator delete, operator new, std::align_val_t, std::launder

namespace io_threads
{

shared_memory_pool::shared_memory_pool(
   size_t const initialPoolCapacity,
   std::align_val_t const memoryAlignment,
   size_t const memorySize
) :
   m_itemAlignment{std::max(memoryAlignment, std::align_val_t{alignof(slist_item)}),},
   m_itemSize{std::max(memorySize, sizeof(slist_item)),}
{
   slist_item *slistHead{nullptr,};
   for (size_t index{0}; initialPoolCapacity > index; ++index)
   {
      auto *memory{allocate(),};
      std::memset(std::bit_cast<void *>(memory), 0, memory_size());
      slistHead = std::launder(std::construct_at<slist_item>(memory, slist_item{.next = slistHead,}));
   }
   m_slistHead.store(slistHead, std::memory_order_release);
}

shared_memory_pool::~shared_memory_pool()
{
   auto *slistHead{m_slistHead.exchange(nullptr, std::memory_order_release),};
   while (nullptr != slistHead)
   {
      auto *item{std::launder(slistHead),};
      slistHead = item->next;
      std::destroy_at(item);
      deallocate(item);
   }
#if (not defined(NDEBUG))
   assert(0 == m_numberOfObjects.load(std::memory_order_relaxed));
#endif
}

std::byte *shared_memory_pool::pop()
{
   auto *item = m_slistHead.load(std::memory_order_relaxed);
   while (
      true
      && (nullptr != item)
      && (
         false == m_slistHead.compare_exchange_strong(
            item,
            item->next,
            std::memory_order_release,
            std::memory_order_relaxed
         )
      )
   )
   {}
   if (nullptr != item) [[likely]]
   {
      std::destroy_at(item);
      return std::launder(std::bit_cast<std::byte *>(item));
   }
   return std::launder(std::bit_cast<std::byte *>(allocate()));
}

void shared_memory_pool::push(std::byte *memory) noexcept
{
   assert(nullptr != memory);
   auto *slistHead = std::launder(
      std::construct_at<slist_item>(
         std::bit_cast<slist_item *>(memory),
         slist_item{.next = m_slistHead.load(std::memory_order_relaxed),}
      )
   );
   while (
      false == m_slistHead.compare_exchange_strong(
         slistHead->next,
         slistHead,
         std::memory_order_release,
         std::memory_order_relaxed
      )
   )
   {}
}

shared_memory_pool::slist_item *shared_memory_pool::allocate()
{
   auto *memory{::operator new(memory_size(), memory_alignment()),};
#if (not defined(NDEBUG))
   m_numberOfObjects.fetch_add(1, std::memory_order_relaxed);
#endif
   return std::launder(std::bit_cast<slist_item *>(memory));
}

void shared_memory_pool::deallocate(slist_item *item)
{
   ::operator delete(item, memory_alignment());
#if (not defined(NDEBUG))
   m_numberOfObjects.fetch_sub(1, std::memory_order_relaxed);
#endif
}

}
