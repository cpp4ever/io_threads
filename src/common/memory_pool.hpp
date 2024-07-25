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

#include "common/utility.hpp" ///< for io_threads::to_underlying

#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <cstddef> ///< for size_t, std::byte
#include <memory> ///< for std::construct_at, std::destroy_at
#include <new> ///< for std::align_val_t, std::launder
#include <type_traits> ///< for std::is_constructible_v, std::is_nothrow_destructible_v, std::is_pointer_v, is_reference_v

namespace io_threads
{

class memory_pool final
{
private:
   struct memory_chunk final
   {
      memory_chunk *next;
   };

public:
   memory_pool() = delete;
   memory_pool(memory_pool &&) = delete;
   memory_pool(memory_pool const &) = delete;
   [[nodiscard]] memory_pool(size_t initialPoolCapacity, std::align_val_t memoryChunkAlignment, size_t memoryChunkSize);
   ~memory_pool();

   memory_pool &operator = (memory_pool &&) = delete;
   memory_pool &operator = (memory_pool const &) = delete;

   [[maybe_unused, nodiscard]] size_t memory_chunk_size() const noexcept
   {
      return m_memoryChunkSize;
   }

   [[nodiscard]] std::byte *pop_memory_chunk();

   template<typename type, typename ...types>
      requires((true == std::is_constructible_v<type, types...>) && (false == std::is_pointer_v<type>) && (false == std::is_reference_v<type>))
   [[maybe_unused, nodiscard]] type &pop_object(types &&...values)
   {
      assert(std::align_val_t{alignof(type)} <= m_memoryChunkAlignment);
      assert(0 == (to_underlying(m_memoryChunkAlignment) % alignof(type)));
      assert(sizeof(type) <= memory_chunk_size());
      return *std::launder(std::construct_at<type>(std::bit_cast<type *>(pop_memory_chunk()), std::forward<types>(values)...));
   }

   void push_memory_chunk(std::byte *memory) noexcept;

   template<typename type>
      requires((false == std::is_pointer_v<type>) && (false == std::is_reference_v<type>))
   [[maybe_unused]] void push_object(type &value) noexcept(true == std::is_nothrow_destructible_v<type>)
   {
      assert(std::align_val_t{alignof(type)} <= m_memoryChunkAlignment);
      assert(0 == (std::bit_cast<uintptr_t>(std::addressof(value)) % to_underlying(m_memoryChunkAlignment)));
      assert(sizeof(type) <= memory_chunk_size());
      std::destroy_at(std::addressof(value));
      push_memory_chunk(std::bit_cast<std::byte *>(std::addressof(value)));
   }

private:
   std::align_val_t const m_memoryChunkAlignment;
   size_t const m_memoryChunkSize;
   memory_chunk *m_memoryChunks{nullptr,};
#if (not defined(NDEBUG))
   intptr_t m_memoryChunksCount{0,};
#endif

   [[nodiscard]] memory_chunk *allocate_memory_chunk()
#if (defined(NDEBUG))
      const
#endif
   ;
   void deallocate_memory_chunk(memory_chunk &memoryChunk)
#if (defined(NDEBUG))
      const
#endif
   ;
};

}
