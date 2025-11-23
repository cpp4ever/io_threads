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

#include "common/websocket_frame_mask.hpp" ///< for io_threads::websocket_frame_mask
#if (defined(__linux__))
#  include "linux/random_generator.hpp" ///< for io_threads::random_generator
#elif (defined(_WIN32) || defined(_WIN64))
#  include "windows/random_generator.hpp" ///< for io_threads::random_generator
#endif

#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <climits> ///< for CHAR_BIT
#include <cstdint> ///< for uint32_t

namespace io_threads
{

void generate_websocket_frame_mask(websocket_frame_mask &websocketFrameMask, random_generator &randomGenerator)
{
   randomGenerator.generate(websocketFrameMask.bytes.data(), websocketFrameMask.bytes.size());
   assert(0 != *std::bit_cast<uint32_t *>(websocketFrameMask.bytes.data()));
}

void next_websocket_frame_mask(websocket_frame_mask &websocketFrameMask)
{
   auto websocketFrameMaskValue{*std::bit_cast<uint32_t *>(websocketFrameMask.bytes.data()),};
   auto const websocketFrameMaskSwapBit{(websocketFrameMaskValue & 0x1) << (websocketFrameMask.bytes.size() * CHAR_BIT - 1),};
   websocketFrameMaskValue = (websocketFrameMaskValue >> 1) | websocketFrameMaskSwapBit;
   assert(0 != websocketFrameMaskValue);
}

}
