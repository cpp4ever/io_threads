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

#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <cstddef> ///< for size_t, std::byte
#include <memory> ///< for std::construct_at, std::destroy_at
#include <new> ///< for std::align_val_t, std::launder
#include <type_traits> ///< for std::is_pointer_v

namespace io_threads
{

class memory_pool final
{
private:
   struct slist_item final
   {
      slist_item *next{nullptr};
   };

public:
   memory_pool() = delete;
   memory_pool(memory_pool &&) = delete;
   memory_pool(memory_pool const &) = delete;
   [[nodiscard]] memory_pool(
      size_t initialPoolCapacity,
      std::align_val_t memoryAlignment,
      size_t memorySize
   );
   ~memory_pool();

   memory_pool &operator = (memory_pool &&) = delete;
   memory_pool &operator = (memory_pool const &) = delete;

   [[maybe_unused, nodiscard]] std::align_val_t memory_alignment() const noexcept
   {
      return m_itemAlignment;
   }

   [[maybe_unused, nodiscard]] size_t memory_size() const noexcept
   {
      return m_itemSize;
   }

   [[maybe_unused, nodiscard]] std::byte *pop();

   template<typename type, typename ...types> requires(false == std::is_pointer_v<type>)
   [[maybe_unused, nodiscard]] type &pop_object(types &&...values)
   {
      assert(std::align_val_t{alignof(type)} <= memory_alignment());
      assert(sizeof(type) <= memory_size());
      return *std::launder(std::construct_at<type>(std::bit_cast<type *>(pop()), std::forward<types>(values)...));
   }

   void push(std::byte *memory) noexcept;

   template<typename type> requires(false == std::is_pointer_v<type>)
   [[maybe_unused]] void push_object(type &value) noexcept(true == std::is_nothrow_destructible_v<type>)
   {
      std::destroy_at(std::addressof(value));
      push(std::bit_cast<std::byte *>(std::addressof(value)));
   }

private:
   slist_item *m_slistHead{nullptr};
#if (not defined(NDEBUG))
   size_t m_numberOfObjects{0};
#endif
   std::align_val_t const m_itemAlignment;
   size_t const m_itemSize;

   [[nodiscard]] slist_item *allocate();
   void deallocate(slist_item *item);
};

}
