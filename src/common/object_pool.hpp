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

#include <algorithm> ///< for std::max
#include <cassert> ///< for assert
#include <cstddef> ///< for size_t
#include <cstring> ///< for std::memset
#include <memory> ///< for std::addressof
#include <new> ///< for std::align_val_t, operator delete, operator new
#include <utility> ///< for std::forward

namespace io_threads
{

template<
   typename object_type,
   std::align_val_t object_alignment = std::align_val_t{alignof(object_type)}
>
class object_pool final
{
private:
   struct slist_item final
   {
      slist_item *next = nullptr;
   };

public:
   object_pool() = delete;
   object_pool(object_pool &&) = delete;
   object_pool(object_pool const &) = delete;

   [[nodiscard]] explicit object_pool(size_t const poolInitialCapacity, size_t const objectSize = sizeof(object_type)) :
      m_objectSize(std::max(objectSize, sizeof(slist_item)))
   {
      assert(sizeof(object_type) <= objectSize);
      for (size_t index = 0; poolInitialCapacity > index; ++index)
      {
         auto *memory = allocate();
         std::memset(memory, 0, object_size());
         m_slistHead = new(memory) slist_item
         {
            .next = m_slistHead,
         };
      }
   }

   ~object_pool()
   {
      while (nullptr != m_slistHead)
      {
         auto *item = m_slistHead;
         m_slistHead = m_slistHead->next;
         item->~slist_item();
         deallocate(item);
      }
      assert(0 == m_numberOfObjects);
   }

   object_pool &operator = (object_pool &&) = delete;
   object_pool &operator = (object_pool const &) = delete;

   [[nodiscard]] size_t object_size() const noexcept
   {
      return m_objectSize;
   }

   template<typename ...types>
   [[nodiscard]] object_type &pop(types &&...values)
   {
      if (nullptr != m_slistHead) [[likely]]
      {
         auto *item = m_slistHead;
         m_slistHead = m_slistHead->next;
         item->~slist_item();
         return *new(item) object_type{std::forward<types>(values)...};
      }
      return *new(allocate()) object_type{std::forward<types>(values)...};
   }

   void push(object_type &item) noexcept
   {
      item.~object_type();
      m_slistHead = new(std::addressof(item)) slist_item
      {
         .next = m_slistHead,
      };
   }

private:
   slist_item *m_slistHead = nullptr;
   size_t m_numberOfObjects = 0;
   size_t const m_objectSize;

   [[nodiscard]] void *allocate()
   {
      ++m_numberOfObjects;
      return ::operator new(object_size(), object_alignment);
   }

   void deallocate(void *value)
   {
      ::operator delete(value, object_alignment);
      --m_numberOfObjects;
   }
};

}
