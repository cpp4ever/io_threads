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

#include "common/logger.hpp" ///< for io_threads::log_system_error
#include "common/utility.hpp" ///< for io_threads::unreachable

#include <sys/random.h> ///< for getrandom

#include <cassert> ///< for assert
#include <cstddef> ///< for size_t, std::byte

namespace io_threads
{

class random_generator final
{
public:
   [[nodiscard]] random_generator() = default;
   random_generator(random_generator &&) = delete;
   random_generator(random_generator const &) = delete;

   random_generator &operator = (random_generator &&) = delete;
   random_generator &operator = (random_generator const &) = delete;

   static void generate(std::byte *bytes, size_t const bytesLength)
   {
      assert(nullptr != bytes);
      assert(0 < bytesLength);
      if (-1 == getrandom(bytes, bytesLength, 0)) [[unlikely]]
      {
         log_system_error("[random] failed to generate random sequence: ({}) - {}", errno);
         unreachable();
      }
   }
};

}
