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

#include <io_threads/data_chunk.hpp>

#include <cassert>
#include <cstring>
#include <string_view>

namespace io_threads::tests
{

class test_string_view_serializer_mock
{
public:
   [[nodiscard]] test_string_view_serializer_mock() noexcept = default;
   [[nodiscard]] test_string_view_serializer_mock(test_string_view_serializer_mock &&rhs) noexcept = default;
   test_string_view_serializer_mock(test_string_view_serializer_mock const &) = delete;

   test_string_view_serializer_mock &operator = (test_string_view_serializer_mock &&) = delete;
   test_string_view_serializer_mock &operator = (test_string_view_serializer_mock const &) = delete;

   [[nodiscard]] size_t finish() noexcept
   {
      auto const bytesWritten{m_bytesWritten,};
      m_dataChunk = {.bytes = nullptr, .bytesLength = 0,};
      m_bytesWritten = 0;
      return bytesWritten;
   }

   void reset(data_chunk const &dataChunk) noexcept
   {
      assert(nullptr != dataChunk.bytes);
      assert(0 < dataChunk.bytesLength);
      assert(nullptr == m_dataChunk.bytes);
      assert(0 == m_dataChunk.bytesLength);
      assert(0 == m_bytesWritten);
      m_dataChunk = dataChunk;
   }

   [[nodiscard]] bool update(std::string_view const &value, size_t &offset)
   {
      assert(value.size() > offset);
      if (m_bytesWritten == m_dataChunk.bytesLength)
      {
         assert(0 == offset);
         return false;
      }
      assert(m_bytesWritten < m_dataChunk.bytesLength);
      auto const bytesToWrite{std::min<size_t>(value.size() - offset, m_dataChunk.bytesLength - m_bytesWritten),};
      assert(0 < bytesToWrite);
      std::memcpy(m_dataChunk.bytes + m_bytesWritten, value.data() + offset, bytesToWrite);
      m_bytesWritten += bytesToWrite;
      offset += bytesToWrite;
      assert(value.size() >= offset);
      return value.size() == offset;
   }

private:
   data_chunk m_dataChunk{.bytes = nullptr, .bytesLength = 0,};
   size_t m_bytesWritten{0,};
};

}
