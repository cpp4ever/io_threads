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

#include "common/logger.hpp" ///< for io_threads::log_error
#include "common/memory_pool.hpp" ///< for io_threads::memory_pool
#include "common/utility.hpp" ///< for io_threads::unreachable
#include "common/websocket_client_handshake_handler.hpp" ///< for io_threads::websocket_client_handshake_handler
#include "common/websocket_client_session.hpp" ///< for io_threads::websocket_client_session, io_threads::websocket_frame_data
#include "common/websocket_error.hpp" ///< for io_threads::make_error_code, io_threads::websocket_error
#include "io_threads/data_chunk.hpp" ///< for io_threads::data_chunk
#include "io_threads/websocket_client_config.hpp" ///< for io_threads::websocket_client_config
#include "io_threads/websocket_frame.hpp" ///< for io_threads::websocket_frame, io_threads::websocket_frame_type
#include "io_threads/wss_client_context.hpp" ///< for io_threads::wss_client_context

/// for
///   Bytef,
///   inflate,
///   uInt,
///   Z_BINARY,
///   Z_OK,
///   z_stream,
///   Z_SYNC_FLUSH,
///   Z_TEXT
#include <zlib.h>

#include <array> ///< for std::to_array
#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <cstddef> ///< for size_t, std::byte
#include <cstring> ///< for std::memcpy
#include <memory> ///< for std::addressof, std::unique_ptr
#include <source_location> ///< for std::source_location
#include <string_view> ///< for std::string_view
#include <system_error> ///< for std::error_code
#include <utility> ///< for std::forward

namespace io_threads
{

class wss_client_context::wss_client_context_impl final
{
public:
   wss_client_context_impl() = delete;
   wss_client_context_impl(wss_client_context_impl &&) = delete;
   wss_client_context_impl(wss_client_context_impl const &) = delete;
   [[nodiscard]] wss_client_context_impl(
      size_t wssSessionListCapacity,
      size_t wssBufferCatacity
   );

   wss_client_context_impl &operator = (wss_client_context_impl &&) = delete;
   wss_client_context_impl &operator = (wss_client_context_impl const &) = delete;

   [[nodiscard]] websocket_client_session &acquire_session();

   [[nodiscard]] size_t format_frame(
      websocket_client_session &session,
      data_chunk const &dataChunk,
      websocket_frame_data const &outboundFrame
   );

   [[nodiscard]] size_t format_handshake_request(
      websocket_client_session &session,
      data_chunk const &dataChunk,
      websocket_client_config const &config,
      std::string_view const &host
   );

   template<typename frame_handler>
   std::error_code handle_frame(
      websocket_client_session &session,
      websocket_frame_data const &inboundFrame,
      frame_handler &&frameHandler
   )
   {
      if (
         false
         || (std::byte{0,} == inboundFrame.header.fin)
         || (inboundFrame.bytesLength < inboundFrame.frameLength)
      )
      {
         return handle_incomplete_frame(session, inboundFrame);
      }
      auto frameOpcode = inboundFrame.header.opcode;
      if (websocket_frame_opcode_continuation == frameOpcode)
      {
         if (nullptr == session.inboundFrame) [[unlikely]]
         {
            return make_error_code(websocket_error::frame_not_finalized);
         }
         frameOpcode = session.inboundFrame->header.opcode;
      }
      switch (to_underlying(frameOpcode))
      {
      case to_underlying(websocket_frame_opcode_text): [[fallthrough]];
      case to_underlying(websocket_frame_opcode_binary):
      return handle_data_frame(session, inboundFrame, frameHandler);

      case to_underlying(websocket_frame_opcode_connection_close):
      {
         handle_connection_close_frame(session, inboundFrame);
      }
      return std::error_code{};

      case to_underlying(websocket_frame_opcode_ping):
      {
         handle_ping_frame(session, inboundFrame);
      }
      return std::error_code{};

      case to_underlying(websocket_frame_opcode_pong):
      {
         /// Do nothing
      }
      return std::error_code{};

      [[unlikely]] default:
      {
         log_error(std::source_location::current(), "[wss_client] unknown frame opcode: {:#X}", to_underlying(frameOpcode));
         unreachable();
      }
      }
   }

   [[nodiscard]] std::error_code handle_handshake_completion(
      websocket_client_session &session,
      data_chunk const &dataChunk
   );

   void ready_to_close(websocket_client_session &session) const;

   void release_session(websocket_client_session &session);

private:
   std::unique_ptr<memory_pool> m_sharedMemory;
   websocket_client_handshake_handler m_handshakeHandler{};
   std::unique_ptr<memory_pool> m_sessionMemory;

   void handle_connection_close_frame(websocket_client_session &session, websocket_frame_data const &inboundConnectionCloseFrame);

   template<typename frame_handler>
   [[nodiscard]] std::error_code handle_data_frame(
      websocket_client_session &session,
      websocket_frame_data const &inboundDataFrame,
      frame_handler &&frameHandler
   )
   {
      assert((std::byte{1,}) == inboundDataFrame.header.fin);
      assert(inboundDataFrame.frameLength == inboundDataFrame.bytesLength);
      assert(0 <= inboundDataFrame.bytesLength);
      assert(nullptr != inboundDataFrame.bytes);
      websocket_frame_data dataFrame{inboundDataFrame,};
      if ((nullptr != session.inboundFrame) && (std::addressof(inboundDataFrame) != session.inboundFrame))
      {
         assert(websocket_frame_opcode_continuation == inboundDataFrame.header.opcode);
         assert(
            false
            || (websocket_frame_opcode_text == session.inboundFrame->header.opcode)
            || (websocket_frame_opcode_binary == session.inboundFrame->header.opcode)
         );
         assert(session.inboundFrame->frameLength == session.inboundFrame->bytesLength);
         if (
            (session.inboundFrame->bytesLength + inboundDataFrame.bytesLength)
               > (m_sharedMemory->memory_chunk_size() - sizeof(websocket_frame_data))
         ) [[unlikely]]
         {
            log_error(
               std::source_location::current(),
               "[wss_client] {} byte frame buffer is too small for {} byte message",
               m_sharedMemory->memory_chunk_size() - sizeof(websocket_frame_data),
               session.inboundFrame->bytesLength + inboundDataFrame.bytesLength
            );
            unreachable();
         }
         std::memcpy(
            session.inboundFrame->bytes + session.inboundFrame->bytesLength,
            inboundDataFrame.bytes,
            inboundDataFrame.bytesLength
         );
         session.inboundFrame->frameLength += inboundDataFrame.frameLength;
         session.inboundFrame->bytesLength += inboundDataFrame.bytesLength;
         dataFrame = *session.inboundFrame;
         dataFrame.header.fin = std::byte{1,};
      }
      else
      {
         assert(
            false
            || (websocket_frame_opcode_text == inboundDataFrame.header.opcode)
            || (websocket_frame_opcode_binary == inboundDataFrame.header.opcode)
         );
      }
      websocket_frame const frame
      {
         .bytes = dataFrame.bytes,
         .bytesLength = dataFrame.bytesLength,
         .type = static_cast<websocket_frame_type>(dataFrame.header.opcode),
      };
      auto const errorCode = (std::byte{0,} == dataFrame.header.rsv1)
         ? frameHandler(frame, true)
         : inflate_frame(session, frame, std::forward<frame_handler>(frameHandler))
      ;
      if (nullptr != session.inboundFrame)
      {
         m_sharedMemory->push_object(*session.inboundFrame);
         session.inboundFrame = nullptr;
      }
      return errorCode;
   }

   [[nodiscard]] std::error_code handle_incomplete_frame(
      websocket_client_session &session,
      websocket_frame_data const &inboundIncompleteFrame
   );

   void handle_ping_frame(websocket_client_session &session, websocket_frame_data const &inboundPingFrame);

   template<typename inflated_frame_handler>
   [[nodiscard]] std::error_code inflate_frame(
      websocket_client_session &session,
      websocket_frame const &frame,
      inflated_frame_handler &&inflatedFrameHandler
   )
   {
      auto &inflateContext{(nullptr == session.inflateContext) ? pop_inflate_stream(-15) : *session.inflateContext};
      auto *inflateBuffer = m_sharedMemory->pop_memory_chunk();
      auto const inflateBufferCapacity = m_sharedMemory->memory_chunk_size();
      inflateContext.next_in = std::bit_cast<Bytef *>(frame.bytes);
      inflateContext.avail_in = static_cast<uInt>(frame.bytesLength);
      inflateContext.total_in = 0;
      inflateContext.next_out = std::bit_cast<Bytef *>(inflateBuffer);
      inflateContext.avail_out = static_cast<uInt>(inflateBufferCapacity);
      inflateContext.total_out = 0;
      inflateContext.data_type = (websocket_frame_type::text == frame.type) ? Z_TEXT : Z_BINARY;
      while (0 < inflateContext.avail_in)
      {
         if (0 == inflateContext.avail_out) [[unlikely]]
         {
            assert(std::bit_cast<Bytef *>(inflateBuffer + inflateBufferCapacity) == inflateContext.next_out);
            websocket_frame const inflatedFrame
            {
               .bytes = inflateBuffer,
               .bytesLength = inflateBufferCapacity,
               .type = frame.type,
            };
            if (auto const errorCode{inflatedFrameHandler(inflatedFrame, false)}; true == bool{errorCode})
            {
               return errorCode;
            }
            inflateContext.next_out = std::bit_cast<Bytef *>(inflateBuffer);
            inflateContext.avail_out = static_cast<uInt>(inflateBufferCapacity);
         }
         if (auto const returnCode{inflate(std::addressof(inflateContext), Z_SYNC_FLUSH)}; Z_OK != returnCode) [[unlikely]]
         {
            log_error(
               std::source_location::current(),
               "[wss_client] failed to inflate: ({}) - {}",
               returnCode,
               std::string_view{inflateContext.msg}
            );
            return make_zlib_error_code(returnCode);
         }
      }
      assert(0 == inflateContext.avail_in);
      assert(std::bit_cast<Bytef *>(inflateBuffer) <= inflateContext.next_out);
      assert(std::bit_cast<Bytef *>(inflateBuffer + inflateBufferCapacity) >= inflateContext.next_out);
      websocket_frame inflatedFrame
      {
         .bytes = inflateBuffer,
         .bytesLength = static_cast<size_t>(inflateContext.next_out - std::bit_cast<Bytef *>(inflateBuffer)),
         .type = frame.type,
      };
      auto finalBytes{std::to_array<Bytef>({0x00, 0x00, 0xff, 0xff})};
      inflateContext.next_in = finalBytes.data();
      inflateContext.avail_in = static_cast<uInt>(finalBytes.size());
      if (auto const returnCode{inflate(std::addressof(inflateContext), Z_SYNC_FLUSH)}; Z_OK != returnCode)
      {
         log_error(
            std::source_location::current(),
            "[wss_client] failed to inflate: ({}) - {}",
            returnCode,
            std::string_view{inflateContext.msg}
         );
         return make_zlib_error_code(returnCode);
      }
      inflatedFrame.bytesLength = static_cast<size_t>(inflateContext.next_out - std::bit_cast<Bytef *>(inflateBuffer));
      if (nullptr == session.inflateContext)
      {
         push_inflate_stream(inflateContext);
      }
      auto const errorCode = inflatedFrameHandler(inflatedFrame, true);
      m_sharedMemory->push_memory_chunk(inflateBuffer);
      return errorCode;
   }

   [[nodiscard]] z_stream &pop_inflate_stream(int const windowBits);
   void push_inflate_stream(z_stream &zlibStream);

   [[nodiscard]] static std::error_code make_zlib_error_code(int value) noexcept;
};

}
