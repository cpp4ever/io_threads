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

#include <array> ///< for std::array
#include <cstddef> ///< for std::byte
#include <cstdint> ///< for uint32_t

namespace io_threads
{

struct sec_websocket_accept final
{
   static constexpr uint32_t sizeof_sha1_digest{20,};
   static constexpr uint32_t sizeof_base64_of_sha1_digest{4 * (sizeof_sha1_digest + 2) / 3 + 1,};

   std::array<std::byte, sizeof_base64_of_sha1_digest> bytes{std::byte{0,},};
   uint32_t bytesLength{0,};
};

struct sec_websocket_key;
class sha1_context;

[[nodiscard]] sec_websocket_accept make_sec_websocket_accept(sec_websocket_key const &secWebSocketKey, sha1_context &sha1Context);

}
