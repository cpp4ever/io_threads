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

#include "io_threads/file_writer.hpp" ///< for io_threads::file_writer

#include <cstddef> ///< for size_t, std::byte
#include <cstdint> ///< for uint32_t, uint8_t
#include <system_error> ///< for std::error_code

namespace io_threads
{

enum struct file_status : uint8_t
{
   none = 0,
   open,
   ready,
   fsync,
   close,
};

struct registered_buffer final
{
   registered_buffer *next{nullptr,};
   uint32_t const index;
   std::byte bytes[1]{std::byte{0,},};

   [[nodiscard]] static constexpr size_t calc_bytes_capacity(size_t const totalSize) noexcept
   {
      return totalSize - offsetof(registered_buffer, bytes);
   }

   [[nodiscard]] static constexpr size_t calc_total_size(size_t const bytesCapacity) noexcept
   {
      return bytesCapacity + offsetof(registered_buffer, bytes);
   }
};

struct file_descriptor final
{
   uint32_t const registeredFileIndex;
   file_status fileStatus{file_status::none,};
   bool closeOnCompletion{false,};
   registered_buffer *registeredBufferInFlight{nullptr,};
   file_writer *fileWriter{nullptr,};
   file_descriptor *next{nullptr,};
   std::error_code closeReason{};
};

}