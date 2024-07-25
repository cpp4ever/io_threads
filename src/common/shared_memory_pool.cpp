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
#include "common/utility.hpp" ///< for io_threads::to_underlying

#include <algorithm> ///< for std::max
#include <atomic> ///< for std::memory_order_acquire, std::memory_order_relaxed
#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <cstddef> ///< for size_t
#include <cstdint> ///< for uintptr_t
#include <cstring> ///< for std::memset
#include <memory> ///< for std::construct_at, std::destroy_at
#include <mutex> ///< for std::scoped_lock
#include <new> ///< for operator delete, operator new, std::align_val_t, std::launder

namespace io_threads
{

shared_memory_pool::shared_memory_pool(
   size_t const initialPoolCapacity,
   std::align_val_t const memoryChunkAlignment,
   size_t const memoryChunkSize
) :
   m_memoryChunkAlignment{std::max<std::align_val_t>(memoryChunkAlignment, std::align_val_t{alignof(memory_chunk)}),},
   m_memoryChunkSize{std::max<size_t>(memoryChunkSize, sizeof(memory_chunk)),}
{
   for (size_t index{0,}; initialPoolCapacity > index; ++index)
   {
      auto *memoryChunk{allocate_memory_chunk(),};
      std::memset(std::bit_cast<void *>(memoryChunk), 0, m_memoryChunkSize);
      m_memoryChunks = std::launder(std::construct_at<memory_chunk>(memoryChunk, memory_chunk{.next = std::launder(m_memoryChunks),}));
   }
}

shared_memory_pool::~shared_memory_pool()
{
   for (memory_chunk *memoryChunks{pop_memory_chunks(),}; nullptr != memoryChunks; )
   {
      auto *memoryChunk{std::launder(memoryChunks),};
      memoryChunks = std::launder(memoryChunk->next);
      memoryChunk->next = nullptr;
      std::destroy_at(memoryChunk);
      deallocate_memory_chunk(*memoryChunk);
   }
#if (not defined(NDEBUG))
   assert(0 == m_memoryChunksCount.load(std::memory_order_acquire));
#endif
}

shared_memory_pool::memory_chunk *shared_memory_pool::allocate_memory_chunk()
#if (defined(NDEBUG))
   const
#endif
{
   auto *memoryChunk{::operator new(m_memoryChunkSize, m_memoryChunkAlignment),};
   assert(nullptr != memoryChunk);
   assert(0 == (std::bit_cast<uintptr_t>(memoryChunk) % to_underlying(m_memoryChunkAlignment)));
#if (not defined(NDEBUG))
   m_memoryChunksCount.fetch_add(1, std::memory_order_relaxed);
#endif
   return std::launder(std::bit_cast<memory_chunk *>(memoryChunk));
}

void shared_memory_pool::deallocate_memory_chunk(memory_chunk &memoryChunk)
#if (defined(NDEBUG))
   const
#endif
{
   assert(0 == (std::bit_cast<uintptr_t>(std::addressof(memoryChunk)) % to_underlying(m_memoryChunkAlignment)));
   ::operator delete(std::addressof(memoryChunk), m_memoryChunkAlignment);
#if (not defined(NDEBUG))
   m_memoryChunksCount.fetch_sub(1, std::memory_order_relaxed);
#endif
}

shared_memory_pool::memory_chunk *shared_memory_pool::pop_memory_chunks()
{
   [[maybe_unused]] std::scoped_lock memoryChunksGuard{m_memoryChunksLock,};
   memory_chunk *memoryChunks{std::launder(m_memoryChunks),};
   m_memoryChunks = nullptr;
   return memoryChunks;
}

}
