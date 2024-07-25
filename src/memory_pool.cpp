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

#include "common/memory_pool.hpp" ///< for io_threads::memory_pool

#include <algorithm> ///< for std::max
#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <cstddef> ///< for size_t, std::byte
#include <cstring> ///< for std::memset
#include <memory> ///< for std::construct_at, std::destroy_at
#include <new> ///< for operator delete, operator new, std::align_val_t, std::launder

namespace io_threads
{

memory_pool::memory_pool(
   size_t const initialPoolCapacity,
   std::align_val_t const memoryAlignment,
   size_t const memorySize
) :
   m_itemAlignment{std::max(memoryAlignment, std::align_val_t{alignof(slist_item)}),},
   m_itemSize{std::max(memorySize, sizeof(slist_item)),}
{
   for (size_t index{0}; initialPoolCapacity > index; ++index)
   {
      auto *memory{allocate(),};
      std::memset(memory, 0, memory_size());
      m_slistHead = std::launder(std::construct_at<slist_item>(memory, slist_item{.next = m_slistHead,}));
   }
}

memory_pool::~memory_pool()
{
   while (nullptr != m_slistHead)
   {
      auto *item{std::launder(m_slistHead),};
      m_slistHead = item->next;
      std::destroy_at(item);
      deallocate(item);
   }
   assert(0 == m_numberOfObjects);
}

std::byte *memory_pool::pop()
{
   if (nullptr != m_slistHead) [[likely]]
   {
      auto *item{std::launder(m_slistHead),};
      m_slistHead = item->next;
      std::destroy_at(item);
      return std::launder(std::bit_cast<std::byte *>(item));
   }
   return std::launder(std::bit_cast<std::byte *>(allocate()));
}

void memory_pool::push(std::byte *memory) noexcept
{
   assert(nullptr != memory);
   m_slistHead = std::launder(
      std::construct_at<slist_item>(
         std::bit_cast<slist_item *>(memory),
         slist_item{.next = m_slistHead,}
      )
   );
}

memory_pool::slist_item *memory_pool::allocate()
{
   auto *memory{::operator new(memory_size(), memory_alignment()),};
   ++m_numberOfObjects;
   return std::launder(std::bit_cast<slist_item *>(memory));
}

void memory_pool::deallocate(slist_item *item)
{
   ::operator delete(item, memory_alignment());
   --m_numberOfObjects;
}

}
