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

#include "common/utility.hpp" ///< for io_threads::to_underlying

#include <atomic> ///< for std::atomic_intptr_t
#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <cstddef> ///< for size_t
#include <cstdint> ///< for uintptr_t
#include <memory> ///< for std::construct_at, std::destroy_at
#include <mutex> ///< for std::mutex, std::scoped_lock
#include <new> ///< for std::align_val_t, std::launder
#include <type_traits> ///< for std::is_constructible_v, std::is_nothrow_destructible_v, std::is_pointer_v, std::is_reference_v
#include <utility> ///< for std::forward

namespace io_threads
{

class shared_memory_pool final
{
private:
   struct memory_chunk final
   {
      memory_chunk *next;
   };

public:
   shared_memory_pool() = delete;
   shared_memory_pool(shared_memory_pool &&) = delete;
   shared_memory_pool(shared_memory_pool const &) = delete;
   [[nodiscard]] shared_memory_pool(size_t initialPoolCapacity, std::align_val_t memoryChunkAlignment, size_t memoryChunkSize);
   ~shared_memory_pool();

   shared_memory_pool &operator = (shared_memory_pool &&) = delete;
   shared_memory_pool &operator = (shared_memory_pool const &) = delete;

   template<typename type, typename ...types>
      requires((true == std::is_constructible_v<type, types...>) && (false == std::is_pointer_v<type>) && (false == std::is_reference_v<type>))
   [[maybe_unused, nodiscard]] type &pop(types &&...values)
   {
      assert(std::align_val_t{alignof(type)} <= m_memoryChunkAlignment);
      assert(0 == (to_underlying(m_memoryChunkAlignment) % alignof(type)));
      assert(sizeof(type) <= m_memoryChunkSize);
      {
         [[maybe_unused]] std::scoped_lock memoryChunksGuard{m_memoryChunksLock,};
         if (nullptr != m_memoryChunks) [[likely]]
         {
            auto *memoryChunk{std::launder(m_memoryChunks),};
            m_memoryChunks = std::launder(memoryChunk->next);
            memoryChunk->next = nullptr;
            std::destroy_at(memoryChunk);
            return *std::launder(std::construct_at<type>(std::bit_cast<type *>(memoryChunk), std::forward<types>(values)...));
         }
      }
      return *std::launder(std::construct_at<type>(std::bit_cast<type *>(allocate_memory_chunk()), std::forward<types>(values)...));
   }

   template<typename type>
      requires((false == std::is_pointer_v<type>) && (false == std::is_reference_v<type>))
   [[maybe_unused]] void push(type &value) noexcept(true == std::is_nothrow_destructible_v<type>)
   {
      assert(std::align_val_t{alignof(type)} <= m_memoryChunkAlignment);
      assert(0 == (std::bit_cast<uintptr_t>(std::addressof(value)) % to_underlying(m_memoryChunkAlignment)));
      assert(sizeof(type) <= m_memoryChunkSize);
      [[maybe_unused]] std::scoped_lock memoryChunksGuard{m_memoryChunksLock,};
      std::destroy_at(std::addressof(value));
      m_memoryChunks = std::launder(
         std::construct_at<memory_chunk>(std::bit_cast<memory_chunk *>(std::addressof(value)), memory_chunk{.next = std::launder(m_memoryChunks),})
      );
   }

private:
   std::align_val_t const m_memoryChunkAlignment;
   size_t const m_memoryChunkSize;
   memory_chunk *m_memoryChunks{nullptr,};
   std::mutex m_memoryChunksLock{};
#if (not defined(NDEBUG))
   std::atomic_intptr_t m_memoryChunksCount{0,};
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

   [[nodiscard]] memory_chunk *pop_memory_chunks();
};

}
