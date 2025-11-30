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

#include "common/memory_pool.hpp" ///< for io_threads::memory_pool

#include <cstddef> ///< for size_t
#include <mutex> ///< for std::mutex, std::scoped_lock
#include <new> ///< for std::align_val_t
#include <type_traits> ///< for std::is_constructible_v, std::is_nothrow_destructible_v, std::is_pointer_v, std::is_reference_v
#include <utility> ///< for std::forward

namespace io_threads
{

class shared_memory_pool final
{
public:
   shared_memory_pool() = delete;
   shared_memory_pool(shared_memory_pool &&) = delete;
   shared_memory_pool(shared_memory_pool const &) = delete;

   [[maybe_unused, nodiscard]] shared_memory_pool(size_t const initialPoolCapacity, std::align_val_t const memoryChunkAlignment, size_t const memoryChunkSize) :
      m_pool{initialPoolCapacity, memoryChunkAlignment, memoryChunkSize,}
   {}

   shared_memory_pool &operator = (shared_memory_pool &&) = delete;
   shared_memory_pool &operator = (shared_memory_pool const &) = delete;

   template<typename type, typename ...types>
      requires((true == std::is_constructible_v<type, types...>) && (false == std::is_pointer_v<type>) && (false == std::is_reference_v<type>))
   [[maybe_unused, nodiscard]] type &pop(types &&...values)
   {
      [[maybe_unused]] std::scoped_lock poolGuard{m_poolLock,};
      return m_pool.pop_object<type>(std::forward<types>(values)...);
   }

   template<typename type>
      requires((false == std::is_pointer_v<type>) && (false == std::is_reference_v<type>))
   [[maybe_unused]] void push(type &value) noexcept(true == std::is_nothrow_destructible_v<type>)
   {
      [[maybe_unused]] std::scoped_lock const poolGuard{m_poolLock,};
      m_pool.push_object(value);
   }

private:
   memory_pool m_pool;
   std::mutex m_poolLock{};
};

}
