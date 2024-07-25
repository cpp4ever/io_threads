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

#include "io_threads/data_chunk.hpp" ///< for io_threads::data_chunk

/// for
///   CHAR,
///   ULONG,
///   WSABUF,
///   WSAOVERLAPPED
#include <WinSock2.h>

#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert

namespace io_threads
{

struct tcp_data_transfer_context final
{
   WSABUF buffer = {.len = 0, .buf = nullptr};
   WSAOVERLAPPED overlapped = {};
};

[[nodiscard]] constexpr WSABUF wsabuf_from_data_chunk(data_chunk const dataChunk) noexcept
{
   return WSABUF{.len = static_cast<ULONG>(dataChunk.size), .buf = std::bit_cast<CHAR *>(dataChunk.data)};
}

[[nodiscard]] constexpr data_chunk wsabuf_to_data_chunk(WSABUF const buffer) noexcept
{
   return data_chunk{.data = buffer.buf, .size = buffer.len};
}

[[nodiscard]] constexpr data_chunk wsabuf_to_data_chunk(WSABUF const buffer, size_t const bytesRecvd) noexcept
{
   assert(bytesRecvd <= buffer.len);
   assert(nullptr != buffer.buf);
   return data_chunk{.data = buffer.buf, .size = bytesRecvd};
}

}
