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

#include <cassert> ///< for assert
#include <cstdint> ///< for intptr_t
#include <stop_token> ///< for std::stop_token

namespace io_threads
{

class uring_stop_token final
{
public:
   uring_stop_token() = delete;
   uring_stop_token(uring_stop_token &&) = delete;
   uring_stop_token(uring_stop_token const &) = delete;

   [[nodiscard]] explicit uring_stop_token(std::stop_token const &stopToken) noexcept :
      m_stopToken(stopToken)
   {}

   ~uring_stop_token()
   {
      assert(0 == m_tasksCount);
   }

   uring_stop_token &operator = (uring_stop_token &&) = delete;
   uring_stop_token &operator = (uring_stop_token const &) = delete;

   void decrement_tasks_count() noexcept
   {
      assert(0 < m_tasksCount);
      --m_tasksCount;
   }

   void increment_tasks_count() noexcept
   {
      ++m_tasksCount;
   }

   [[nodiscard]] bool stop_possible() const noexcept
   {
      return 0 == m_tasksCount;
   }

   [[nodiscard]] bool stop_requested() const noexcept
   {
      return m_stopToken.stop_requested();
   }

private:
   intptr_t m_tasksCount{0,};
   std::stop_token const &m_stopToken;
};

}
