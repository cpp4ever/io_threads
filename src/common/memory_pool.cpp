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

#include "common/memory_pool.hpp" ///< for io_threads::memory_pool
#include "common/utility.hpp" ///< for io_threads::to_underlying

#include <algorithm> ///< for std::max
#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <cstddef> ///< for size_t, std::byte
#include <cstdint> ///< for uintptr_t
#include <cstring> ///< for std::memset
#include <memory> ///< for std::construct_at, std::destroy_at
#include <new> ///< for operator delete, operator new, std::align_val_t

namespace io_threads
{

memory_pool::memory_pool(
   size_t const initialPoolCapacity,
   std::align_val_t const memoryChunkAlignment,
   size_t const memoryChunkSize
) :
   m_memoryChunkAlignment{std::max<std::align_val_t>(memoryChunkAlignment, std::align_val_t{alignof(memory_chunk)}),},
   m_memoryChunkSize{std::max<size_t>(memoryChunkSize, sizeof(memory_chunk)),}
{
#if (defined(NDEBUG))
   auto const bytesStep
   {
      (0 == (m_memoryChunkSize % to_underlying(m_memoryChunkAlignment)))
         ? m_memoryChunkSize
         : (m_memoryChunkSize + to_underlying(m_memoryChunkAlignment) - (m_memoryChunkSize % to_underlying(m_memoryChunkAlignment)))
      ,
   };
   auto const bytesLength{bytesStep * initialPoolCapacity,};
   m_headMemoryChunk = std::bit_cast<std::byte *>(::operator new(bytesLength, m_memoryChunkAlignment));
   m_tailMemoryChunk = m_headMemoryChunk + bytesLength;
   std::memset(m_headMemoryChunk, 0, bytesLength);
#endif
   for (size_t index{0,}; initialPoolCapacity > index; ++index)
   {
#if (defined(NDEBUG))
      auto *memoryChunk{std::bit_cast<memory_chunk *>(m_headMemoryChunk + bytesStep * index),};
      assert(m_tailMemoryChunk > memoryChunk);
      assert((memoryChunk + bytesStep * (index + 1)) <= m_tailMemoryChunk);
#else
      auto *memoryChunk{allocate_memory_chunk(),};
      std::memset(std::bit_cast<void *>(memoryChunk), 0, memory_chunk_size());
#endif
      m_memoryChunks = std::construct_at<memory_chunk>(memoryChunk, memory_chunk{.next = m_memoryChunks,});
   }
}

memory_pool::~memory_pool()
{
   while (nullptr != m_memoryChunks)
   {
      auto *memoryChunk{m_memoryChunks,};
      m_memoryChunks = memoryChunk->next;
      memoryChunk->next = nullptr;
      std::destroy_at(memoryChunk);
#if (defined(NDEBUG))
      if (auto *bytes{std::bit_cast<std::byte *>(memoryChunk),}; (bytes >= m_headMemoryChunk) && (bytes < m_tailMemoryChunk))
      {
         continue;
      }
#endif
      deallocate_memory_chunk(*memoryChunk);
   }
#if (defined(NDEBUG))
   ::operator delete(m_headMemoryChunk, m_memoryChunkAlignment);
#else
   assert(0 == m_memoryChunksCount);
#endif
}

std::byte *memory_pool::pop_memory_chunk()
{
   if (nullptr != m_memoryChunks) [[likely]]
   {
      auto *memoryChunk{m_memoryChunks,};
      m_memoryChunks = memoryChunk->next;
      memoryChunk->next = nullptr;
      std::destroy_at(memoryChunk);
      return std::bit_cast<std::byte *>(memoryChunk);
   }
   return std::bit_cast<std::byte *>(allocate_memory_chunk());
}

void memory_pool::push_memory_chunk(std::byte *memory) noexcept
{
   assert(nullptr != memory);
   assert(0 == (std::bit_cast<uintptr_t>(memory) % to_underlying(m_memoryChunkAlignment)));
   m_memoryChunks = std::construct_at<memory_chunk>(std::bit_cast<memory_chunk *>(memory), memory_chunk{.next = m_memoryChunks,});
}

memory_pool::memory_chunk *memory_pool::allocate_memory_chunk()
#if (defined(NDEBUG))
   const
#endif
{
   auto *memoryChunk{::operator new(memory_chunk_size(), m_memoryChunkAlignment),};
   assert(nullptr != memoryChunk);
   assert(0 == (std::bit_cast<uintptr_t>(memoryChunk) % to_underlying(m_memoryChunkAlignment)));
#if (not defined(NDEBUG))
   ++m_memoryChunksCount;
#endif
   return std::bit_cast<memory_chunk *>(memoryChunk);
}

void memory_pool::deallocate_memory_chunk(memory_chunk &memoryChunk)
#if (defined(NDEBUG))
   const
#endif
{
   assert(0 == (std::bit_cast<uintptr_t>(std::addressof(memoryChunk)) % to_underlying(m_memoryChunkAlignment)));
   ::operator delete(std::addressof(memoryChunk), m_memoryChunkAlignment);
#if (not defined(NDEBUG))
   --m_memoryChunksCount;
#endif
}

}
