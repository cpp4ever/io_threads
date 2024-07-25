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

#include <immintrin.h> ///< for _mm_pause

/// for
///   ATOMIC_FLAG_INIT,
///   std::atomic_flag,
///   std::memory_order_acq_rel,
///   std::memory_order_relaxed,
///   std::memory_order_release
#include <atomic>
#include <version> ///< for __cplusplus, __cpp_lib_atomic_flag_test

namespace io_threads
{

class spin_lock final
{
public:
   [[nodiscard]] spin_lock() noexcept = default;
   spin_lock(spin_lock const &) = delete;
   spin_lock(spin_lock &&) = delete;

   spin_lock &operator = (spin_lock const &) = delete;
   spin_lock &operator = (spin_lock &&) = delete;

   void lock() noexcept
   {
      while (m_atomicFlag.test_and_set(std::memory_order_acq_rel))
      {
#if (201907L <= __cpp_lib_atomic_flag_test)
         while (m_atomicFlag.test(std::memory_order_relaxed))
#endif
         {
            _mm_pause();
         }
      }
   }

   void unlock() noexcept
   {
      m_atomicFlag.clear(std::memory_order_release);
   }

private:
#if (202002L <= __cplusplus)
   std::atomic_flag m_atomicFlag = {};
#else
   std::atomic_flag m_atomicFlag = ATOMIC_FLAG_INIT;
#endif
};

}
