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

#include "common/logger.hpp" ///< for io_threads::log_error, io_threads::log_system_error
#include "common/utility.hpp" ///< for io_threads::unreachable

#include <array> ///< for std::array
#include <bit> ///< for std::bit_cast
#include <cstddef> ///< for size_t, std::byte
#include <memory> ///< for std::addressof
#include <new> ///< for operator delete, operator new, std::align_val_t
#include <source_location> ///< for std::source_location

namespace io_threads
{

constexpr size_t sha1_digest_size = 20;
using sha1_digest = std::array<std::byte, sha1_digest_size>;

class sha1_context final
{
public:
   [[nodiscard]] sha1_context() = default;
   sha1_context(sha1_context &&) = delete;
   sha1_context(sha1_context const &) = delete;

   ~sha1_context()
   {
   }

   sha1_context &operator = (sha1_context &&) = delete;
   sha1_context &operator = (sha1_context const &) = delete;

   [[nodiscard]] sha1_digest finish() const
   {
      sha1_digest digest{};
      return digest;
   }

   void update(std::byte const *bytes, size_t const bytesLength)
   {
      (void)bytes;
      (void)bytesLength;
   }
};

}
