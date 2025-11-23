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

#include "common/sec_websocket_key.hpp" ///< for io_threads::sec_websocket_key
#include "common/websocket_frame_mask.hpp" ///< for io_threads::websocket_frame_mask
#include "io_threads/websocket_frame.hpp" /// < for io_threads::websocket_frame

#include <zlib.h> ///< for z_stream

#include <array> ///< for std::array
#include <cstddef> ///< for size_t, std::byte
#include <cstdint> ///< for uint32_t, uint8_t

namespace io_threads
{

constexpr std::byte websocket_frame_opcode_continuation{0x0,};
constexpr std::byte websocket_frame_opcode_text{0x1,};
constexpr std::byte websocket_frame_opcode_binary{0x2,};
constexpr std::byte websocket_frame_opcode_connection_close{0x8,};
constexpr std::byte websocket_frame_opcode_ping{0x9,};
constexpr std::byte websocket_frame_opcode_pong{0xA,};
constexpr std::byte websocket_frame_mask_flag{1 << 7,};
constexpr size_t websocket_frame_max_tiny_payload_size{125,};
constexpr std::byte websocket_frame_short_payload_flag{126,};
constexpr size_t websocket_frame_max_short_payload_size{64 * 1024,};
constexpr std::byte websocket_frame_long_payload_flag{127,};

struct websocket_frame_header final
{
   std::byte opcode : 4{std::byte{0,},};
   std::byte rsv3 : 1{std::byte{0,},};
   std::byte rsv2 : 1{std::byte{0,},};
   std::byte rsv1 : 1{std::byte{0,},};
   std::byte fin : 1{std::byte{0,},};
};

struct websocket_frame_data final
{
   websocket_frame_header header{};
#if (not defined(NDEBUG))
   uint8_t partsCount{0,};
#endif
   uint32_t frameLength{0,};
   uint32_t bytesLength{0,};
   std::byte *bytes{nullptr,};
};

struct websocket_client_session final
{
   websocket_frame_data *inboundFrame{nullptr,};
   websocket_frame_data *outboundFrame{nullptr,};
   websocket_frame_mask outboundFrameMask{};
   z_stream *inflateContext{nullptr,};
   sec_websocket_key *handshakeKey{nullptr,};
   bool closed{false,};
   uint8_t incompleteInboundFrameLength{0,};
   std::array<std::byte, 10> incompleteInboundFrame{std::byte{0,},};
};

}
