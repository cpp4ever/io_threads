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

#include "common/logger.hpp" ///< for io_threads::log_error
#include "common/memory_pool.hpp" ///< for io_threads::memory_pool
#include "common/sec_websocket_key.hpp" ///< for io_threads::sec_websocket_key
#include "common/utility.hpp" ///< for io_threads::unreachable
#include "common/websocket_client_session.hpp" ///< for io_threads::websocket_client_session, io_threads::websocket_frame_data
#include "common/websocket_error.hpp" ///< for io_threads::make_error_code, io_threads::websocket_error
#include "common/websocket_frame_mask.hpp" ///< for io_threads::next_websocket_frame_mask
#include "common/wss_client_context_impl.hpp" ///< for io_threads::wss_client_context::wss_client_context_impl
#include "io_threads/data_chunk.hpp" ///< for io_threads::data_chunk
#include "io_threads/websocket_client_config.hpp" ///< for io_threads::websocket_client_config
#include "io_threads/wss_client_context.hpp" ///< for io_threads::wss_client_context

#if (defined(__linux__))
#  include <endian.h> ///< for htobe16, htobe64
#  define htonll htobe64
#  define htons htobe16
#elif (defined(_WIN32) || defined(_WIN64))
#  include <WinSock2.h> ///< for htonll, htons
#endif
/// for
///   inflateEnd,
///   inflateInit2,
///   uInt,
///   voidpf,
///   Z_OK,
///   z_stream,
///   zError
#include <zlib.h>
#include <deflate.h> ///< for deflate_state
#include <inftrees.h> ///< for inflate.h
#include <inflate.h> ///< for inflate_state

#include <algorithm> ///< for std::max
#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <cstddef> ///< for size_t, std::byte
#include <cstdint> ///< for uint16_t, uint32_t, uint64_t, uint8_t
#include <cstring> ///< for std::memcpy
#include <memory> ///< for std::addressof, std::construct_at, std::destroy_at, std::make_unique
#include <new> ///< for std::align_val_t, std::launder
#include <source_location> ///< for std::source_location
#include <string> ///< for std::string
#include <string_view> ///< for std::string_view
#include <system_error> ///< for std::error_category, std::error_code

namespace io_threads
{

namespace
{

struct zlib_allocator final
{
   std::byte *bytes{nullptr,};
   size_t bytesCapacity{0,};

   [[nodiscard]] static voidpf allocate(voidpf userdata, uInt const items, uInt const itemSize)
   {
      assert(nullptr != userdata);
      auto &allocator{*std::bit_cast<zlib_allocator *>(userdata),};
      auto const allocSize{items * itemSize,};
      assert(allocSize <= allocator.bytesCapacity);
      auto *memory{allocator.bytes,};
      allocator.bytes += allocSize;
      allocator.bytesCapacity -= allocSize;
      return std::launder(memory);
   }

   static void deallocate(voidpf, voidpf) noexcept
   {
      /// Do nothing
   }
};

}

wss_client_context::wss_client_context_impl::wss_client_context_impl(
   uint32_t const sessionListCapacity,
   uint32_t const inboundBufferSize,
   uint32_t const outboundBufferSize
) :
   //m_deflatePool
   //{
   //   std::make_unique<memory_pool>(
   //      1,
   //      std::align_val_t{alignof(z_stream),},
   //      sizeof(z_stream) + sizeof(zlib_allocator) + sizeof(deflate_state) + 256 * 1024
   //   ),
   //},
   m_inflatePool
   {
      std::make_unique<memory_pool>(
         1,
         std::align_val_t{alignof(z_stream),},
         sizeof(z_stream) + sizeof(zlib_allocator) + sizeof(inflate_state) + 32 * 1024
      ),
   },
   m_inboundFramePool
   {
      std::make_unique<memory_pool>(sessionListCapacity + 1, std::align_val_t{alignof(websocket_frame_data),}, sizeof(websocket_frame_data) + inboundBufferSize),
   },
   m_outboundFramePool
   {
      std::make_unique<memory_pool>(
         sessionListCapacity,
         std::align_val_t{std::max(alignof(sec_websocket_key), alignof(websocket_frame_data)),},
         std::max(sizeof(websocket_frame_data) + outboundBufferSize, sizeof(sec_websocket_key))
      ),
   },
   m_sessionPool
   {
      std::make_unique<memory_pool>(sessionListCapacity, std::align_val_t{alignof(websocket_client_session),}, sizeof(websocket_client_session)),
   }
{}

websocket_client_session &wss_client_context::wss_client_context_impl::acquire_session()
{
   auto &session{m_sessionPool->pop_object<websocket_client_session>(),};
   session.handshakeKey = std::addressof(m_outboundFramePool->pop_object<sec_websocket_key>());
   return session;
}

size_t wss_client_context::wss_client_context_impl::format_frame(
   websocket_client_session &session,
   data_chunk const &dataChunk,
   websocket_frame_data const &outboundFrame
)
{
   size_t bytesWritten;
   dataChunk.bytes[0] = std::bit_cast<std::byte>(outboundFrame.header);
   if (websocket_frame_max_tiny_payload_size >= outboundFrame.bytesLength)
   {
      auto const tinyBytesLength{static_cast<uint8_t>(outboundFrame.bytesLength),};
      dataChunk.bytes[1] = websocket_frame_mask_flag | std::byte{tinyBytesLength};
      bytesWritten = 2;
   }
   else if (websocket_frame_max_short_payload_size >= outboundFrame.bytesLength)
   {
      dataChunk.bytes[1] = websocket_frame_mask_flag | websocket_frame_short_payload_flag;
      auto const shortBytesLength{htons(static_cast<uint16_t>(outboundFrame.bytesLength)),};
      std::memcpy(std::addressof(dataChunk.bytes[2]), std::addressof(shortBytesLength), sizeof(shortBytesLength));
      bytesWritten = 4;
   }
   else
   {
      dataChunk.bytes[1] = websocket_frame_mask_flag | websocket_frame_long_payload_flag;
      auto const longBytesLength{htonll(static_cast<uint64_t>(outboundFrame.bytesLength)),};
      std::memcpy(std::addressof(dataChunk.bytes[2]), std::addressof(longBytesLength), sizeof(longBytesLength));
      bytesWritten = 10;
   }
   auto &frameMask{session.outboundFrameMask,};
   std::memcpy(std::addressof(dataChunk.bytes[bytesWritten]), frameMask.bytes.data(), frameMask.bytes.size());
   bytesWritten += frameMask.bytes.size();
   auto const *outboundBytes{outboundFrame.bytes,};
   auto outboundBytesLength{outboundFrame.bytesLength,};
   while (frameMask.bytes.size() < outboundBytesLength)
   {
      for (size_t frameMaskByteIndex{0,}; frameMask.bytes.size() > frameMaskByteIndex; ++frameMaskByteIndex, ++bytesWritten)
      {
         dataChunk.bytes[bytesWritten] = outboundBytes[frameMaskByteIndex] ^ frameMask.bytes[frameMaskByteIndex];
      }
      outboundBytes += frameMask.bytes.size();
      outboundBytesLength -= static_cast<uint32_t>(frameMask.bytes.size());
   }
   for (size_t frameMaskByteIndex{0,}; frameMaskByteIndex < outboundBytesLength; ++frameMaskByteIndex, ++bytesWritten)
   {
      dataChunk.bytes[bytesWritten] = outboundBytes[frameMaskByteIndex] ^ frameMask.bytes[frameMaskByteIndex];
   }
   next_websocket_frame_mask(frameMask);
   if (std::addressof(outboundFrame) == session.outboundFrame)
   {
      m_outboundFramePool->push_object(*session.outboundFrame);
      session.outboundFrame = nullptr;
   }
   else
   {
      assert(nullptr == session.outboundFrame);
   }
   return bytesWritten;
}

size_t wss_client_context::wss_client_context_impl::format_handshake_request(
   websocket_client_session &session,
   data_chunk const &dataChunk,
   websocket_client_config const &config,
   std::string_view const &host
)
{
   assert(nullptr != session.handshakeKey);
   assert(nullptr != dataChunk.bytes);
   assert(0 < dataChunk.bytesLength);
   assert(false == config.target().empty());
   assert(false == host.empty());
   return m_handshakeHandler.build_request(session, dataChunk, config, host);
}

std::error_code wss_client_context::wss_client_context_impl::handle_handshake_completion(
   websocket_client_session &session,
   data_chunk const &dataChunk
)
{
   assert(nullptr != session.handshakeKey);
   assert(nullptr != dataChunk.bytes);
   assert(0 < dataChunk.bytesLength);
   auto const errorCode
   {
      m_handshakeHandler.handle_response(
         session,
         std::string_view{std::bit_cast<char const *>(dataChunk.bytes), dataChunk.bytesLength}
      ),
   };
   m_outboundFramePool->push_object(*session.handshakeKey);
   session.handshakeKey = nullptr;
   return errorCode;
}

void wss_client_context::wss_client_context_impl::ready_to_close(websocket_client_session &session, uint16_t closureReason) const
{
   if (false == session.closed)
   {
      auto &outboundConnectionCloseFrame
      {
         (nullptr == session.outboundFrame)
            ? m_outboundFramePool->pop_object<websocket_frame_data>(websocket_frame_data{})
            : *session.outboundFrame
         ,
      };
      outboundConnectionCloseFrame.header.opcode = websocket_frame_opcode_connection_close;
      outboundConnectionCloseFrame.header.fin = std::byte{1,};
      outboundConnectionCloseFrame.bytes = std::bit_cast<std::byte *>(std::addressof(outboundConnectionCloseFrame) + 1);
      closureReason = htons(closureReason);
      std::memcpy(outboundConnectionCloseFrame.bytes, std::addressof(closureReason), sizeof(closureReason));
      outboundConnectionCloseFrame.bytesLength = sizeof(closureReason);
      session.closed = true;
      session.outboundFrame = std::addressof(outboundConnectionCloseFrame);
   }
}

void wss_client_context::wss_client_context_impl::release_session(websocket_client_session &session)
{
   if (nullptr != session.inboundFrame)
   {
      m_inboundFramePool->push_object(*session.inboundFrame);
      session.inboundFrame = nullptr;
   }
   if (nullptr != session.outboundFrame)
   {
      m_outboundFramePool->push_object(*session.outboundFrame);
      session.outboundFrame = nullptr;
   }
   if (nullptr != session.inflateContext)
   {
      push_inflate_stream(*session.inflateContext);
      session.inflateContext = nullptr;
   }
   if (nullptr != session.handshakeKey)
   {
      m_outboundFramePool->push_object(*session.handshakeKey);
      session.handshakeKey = nullptr;
   }
   m_sessionPool->push_object(session);
}

void wss_client_context::wss_client_context_impl::handle_connection_close_frame(
   websocket_client_session &session,
   websocket_frame_data const &inboundConnectionCloseFrame
)
{
   assert((std::byte{1,}) == inboundConnectionCloseFrame.header.fin);
   assert(inboundConnectionCloseFrame.frameLength == inboundConnectionCloseFrame.bytesLength);
   assert(nullptr != inboundConnectionCloseFrame.bytes);
   if (true == session.closed)
   {
      if (nullptr != session.inboundFrame)
      {
         assert(websocket_frame_opcode_connection_close == session.inboundFrame->header.opcode);
         assert(websocket_frame_opcode_continuation == inboundConnectionCloseFrame.header.opcode);
         m_inboundFramePool->push_object(*session.inboundFrame);
         session.inboundFrame = nullptr;
      }
      else
      {
         assert(websocket_frame_opcode_connection_close == inboundConnectionCloseFrame.header.opcode);
      }
      if (nullptr != session.outboundFrame)
      {
         m_outboundFramePool->push_object(*session.outboundFrame);
         session.outboundFrame = nullptr;
      }
   }
   else
   {
      session.closed = true;
      if (nullptr == session.outboundFrame)
      {
         session.outboundFrame = std::addressof(m_outboundFramePool->pop_object<websocket_frame_data>(websocket_frame_data{}));
      }
      auto &outboundFrame = *session.outboundFrame;
      outboundFrame.frameLength = 0;
      outboundFrame.bytesLength = 0;
      outboundFrame.bytes = std::bit_cast<std::byte *>(session.outboundFrame + 1);
      if ((nullptr != session.inboundFrame) && (std::addressof(inboundConnectionCloseFrame) != session.inboundFrame))
      {
         assert(websocket_frame_opcode_continuation == inboundConnectionCloseFrame.header.opcode);
         assert(websocket_frame_opcode_connection_close == session.inboundFrame->header.opcode);
         assert(session.inboundFrame->frameLength == session.inboundFrame->bytesLength);
         if (
            (session.inboundFrame->bytesLength + inboundConnectionCloseFrame.bytesLength)
               > (m_outboundFramePool->memory_chunk_size() - sizeof(websocket_frame_data))
         ) [[unlikely]]
         {
            log_error(
               std::source_location::current(),
               "[wss_client] {} byte frame buffer is too small for {} byte message",
               m_outboundFramePool->memory_chunk_size() - sizeof(websocket_frame_data),
               session.inboundFrame->bytesLength + inboundConnectionCloseFrame.bytesLength
            );
            unreachable();
         }
#if (not defined(NDEBUG))
         session.inboundFrame->partsCount += inboundConnectionCloseFrame.partsCount;
#endif
         outboundFrame.header = session.inboundFrame->header;
         outboundFrame.header.fin = inboundConnectionCloseFrame.header.fin;
         std::memcpy(
            outboundFrame.bytes,
            session.inboundFrame->bytes,
            session.inboundFrame->bytesLength
         );
         outboundFrame.frameLength = session.inboundFrame->frameLength;
         outboundFrame.bytesLength = session.inboundFrame->bytesLength;
         m_inboundFramePool->push_object(*session.inboundFrame);
         session.inboundFrame = nullptr;
      }
      else
      {
         assert(websocket_frame_opcode_connection_close == inboundConnectionCloseFrame.header.opcode);
         outboundFrame.header = inboundConnectionCloseFrame.header;
      }
      std::memcpy(
         outboundFrame.bytes + outboundFrame.bytesLength,
         inboundConnectionCloseFrame.bytes,
         inboundConnectionCloseFrame.bytesLength
      );
      outboundFrame.frameLength += inboundConnectionCloseFrame.frameLength;
      outboundFrame.bytesLength += inboundConnectionCloseFrame.bytesLength;
      assert(outboundFrame.frameLength == outboundFrame.bytesLength);
   }
}

std::error_code wss_client_context::wss_client_context_impl::handle_incomplete_frame(
   websocket_client_session &session,
   websocket_frame_data const &inboundIncompleteFrame
)
{
   assert(
      false
      || ((std::byte{0,}) == inboundIncompleteFrame.header.fin)
      || (inboundIncompleteFrame.bytesLength < inboundIncompleteFrame.frameLength)
   );
   assert(nullptr != inboundIncompleteFrame.bytes);
   if (nullptr == session.inboundFrame)
   {
      assert(std::addressof(inboundIncompleteFrame) != session.inboundFrame);
      if (websocket_frame_opcode_continuation == inboundIncompleteFrame.header.opcode) [[unlikely]]
      {
         return make_error_code(websocket_error::frame_opcode_not_specified);
      }
      session.inboundFrame = std::addressof(
         m_inboundFramePool->pop_object<websocket_frame_data>(websocket_frame_data{.header = inboundIncompleteFrame.header,})
      );
      session.inboundFrame->bytes = std::bit_cast<std::byte *>(session.inboundFrame + 1);
   }
   else
   {
      assert((std::byte{0,}) == inboundIncompleteFrame.header.rsv1);
      if (websocket_frame_opcode_continuation != inboundIncompleteFrame.header.opcode) [[unlikely]]
      {
         m_inboundFramePool->push_object(*session.inboundFrame);
         session.inboundFrame = nullptr;
         return make_error_code(websocket_error::frame_not_finalized);
      }
      session.inboundFrame->header.fin = inboundIncompleteFrame.header.fin;
   }
   if (
      (session.inboundFrame->bytesLength + inboundIncompleteFrame.bytesLength)
         > (m_inboundFramePool->memory_chunk_size() - sizeof(websocket_frame_data))
   ) [[unlikely]]
   {
      log_error(
         std::source_location::current(),
         "[wss_client] {} byte frame buffer is too small for {} byte message",
         m_inboundFramePool->memory_chunk_size() - sizeof(websocket_frame_data),
         session.inboundFrame->bytesLength + inboundIncompleteFrame.bytesLength
      );
      unreachable();
   }
#if (not defined(NDEBUG))
   session.inboundFrame->partsCount += inboundIncompleteFrame.partsCount;
#endif
   std::memcpy(
      session.inboundFrame->bytes + session.inboundFrame->bytesLength,
      inboundIncompleteFrame.bytes,
      inboundIncompleteFrame.bytesLength
   );
   session.inboundFrame->frameLength += inboundIncompleteFrame.frameLength;
   session.inboundFrame->bytesLength += inboundIncompleteFrame.bytesLength;
   assert(session.inboundFrame->bytesLength <= session.inboundFrame->frameLength);
   return std::error_code{};
}

void wss_client_context::wss_client_context_impl::handle_ping_frame(
   websocket_client_session &session,
   websocket_frame_data const &inboundPingFrame
)
{
   assert((std::byte{1,}) == inboundPingFrame.header.fin);
   assert(inboundPingFrame.frameLength == inboundPingFrame.bytesLength);
   assert(nullptr != inboundPingFrame.bytes);
   if ((false == session.closed) && (nullptr == session.outboundFrame)) [[likely]]
   {
      auto &outboundFrame{m_outboundFramePool->pop_object<websocket_frame_data>(websocket_frame_data{}),};
      outboundFrame.bytes = std::bit_cast<std::byte *>(std::addressof(outboundFrame) + 1);
      if ((nullptr != session.inboundFrame) && (std::addressof(inboundPingFrame) != session.inboundFrame)) [[unlikely]]
      {
         assert(websocket_frame_opcode_continuation == inboundPingFrame.header.opcode);
         assert(websocket_frame_opcode_ping == session.inboundFrame->header.opcode);
         assert(session.inboundFrame->frameLength == session.inboundFrame->bytesLength);
         if (
            (session.inboundFrame->bytesLength + inboundPingFrame.bytesLength)
               > (m_outboundFramePool->memory_chunk_size() - sizeof(websocket_frame_data))
         ) [[unlikely]]
         {
            log_error(
               std::source_location::current(),
               "[wss_client] {} byte frame buffer is too small for {} byte message",
               m_outboundFramePool->memory_chunk_size() - sizeof(websocket_frame_data),
               session.inboundFrame->bytesLength + inboundPingFrame.bytesLength
            );
            unreachable();
         }
#if (not defined(NDEBUG))
         session.inboundFrame->partsCount += inboundPingFrame.partsCount;
#endif
         outboundFrame.header = session.inboundFrame->header;
         outboundFrame.header.fin = inboundPingFrame.header.fin;
         std::memcpy(
            outboundFrame.bytes,
            session.inboundFrame->bytes,
            session.inboundFrame->bytesLength
         );
         outboundFrame.frameLength = session.inboundFrame->frameLength;
         outboundFrame.bytesLength = session.inboundFrame->bytesLength;
         m_inboundFramePool->push_object(*session.inboundFrame);
         session.inboundFrame = nullptr;
      }
      else
      {
         assert(websocket_frame_opcode_ping == inboundPingFrame.header.opcode);
         outboundFrame.header = inboundPingFrame.header;
      }
      std::memcpy(
         outboundFrame.bytes + outboundFrame.bytesLength,
         inboundPingFrame.bytes,
         inboundPingFrame.bytesLength
      );
      outboundFrame.frameLength += inboundPingFrame.frameLength;
      outboundFrame.bytesLength += inboundPingFrame.bytesLength;
      assert(outboundFrame.frameLength == outboundFrame.bytesLength);
      session.outboundFrame = std::addressof(outboundFrame);
   }
}

z_stream &wss_client_context::wss_client_context_impl::pop_inflate_stream(int const windowBits)
{
   auto &zlibStream{m_inflatePool->pop_object<z_stream>(),};
   auto *zlibAllocator
   {
      std::launder(
         std::construct_at<zlib_allocator>(
            std::bit_cast<zlib_allocator *>(std::addressof(zlibStream) + 1),
            zlib_allocator
            {
               .bytes = std::bit_cast<std::byte *>(std::addressof(zlibStream) + 1) + sizeof(zlib_allocator),
               .bytesCapacity = m_inflatePool->memory_chunk_size() - sizeof(z_stream) - sizeof(zlib_allocator),
            }
         )
      ),
   };
   zlibStream.opaque = zlibAllocator;
   zlibStream.zalloc = zlib_allocator::allocate;
   zlibStream.zfree = zlib_allocator::deallocate;
   if (auto const returnCode{inflateInit2(std::addressof(zlibStream), windowBits),}; Z_OK != returnCode) [[unlikely]]
   {
      log_error(
         std::source_location::current(),
         "[wss_client] failed to initialize inflate context: {}",
         returnCode
      );
      unreachable();
   }
   return zlibStream;
}

void wss_client_context::wss_client_context_impl::push_inflate_stream(z_stream &zlibStream)
{
   if (auto const returnCode{inflateEnd(std::addressof(zlibStream)),}; Z_OK != returnCode)
   {
      log_error(
         std::source_location::current(),
         "[wss_client] failed to deinitialize inflate context: {}",
         returnCode
      );
      unreachable();
   }
   zlibStream.zalloc = nullptr;
   zlibStream.zfree = nullptr;
   std::destroy_at(std::bit_cast<zlib_allocator *>(zlibStream.opaque));
   zlibStream.opaque = nullptr;
   m_inflatePool->push_object(zlibStream);
}

namespace
{

struct zlib_error_category final
{
private:
   class zlib_error_category_impl final : public std::error_category
   {
   public:
      [[nodiscard]] constexpr zlib_error_category_impl() noexcept = default;
      zlib_error_category_impl(zlib_error_category_impl &&) = delete;
      zlib_error_category_impl(zlib_error_category_impl const &) = delete;

      zlib_error_category_impl &operator = (zlib_error_category_impl &&) = delete;
      zlib_error_category_impl &operator = (zlib_error_category_impl const &) = delete;

      [[nodiscard]] const char *name() const noexcept override
      {
         return "zlib";
      }

      [[nodiscard]] std::string message(int const value) const override
      {
         return std::string{zError(value),};
      }
   };

   static inline zlib_error_category_impl impl{};

public:
   [[nodiscard]] static std::error_category const &instance() noexcept
   {
      return impl;
   }
};

}

std::error_code wss_client_context::wss_client_context_impl::make_zlib_error_code(int const errorCode) noexcept
{
   return std::error_code{errorCode, zlib_error_category::instance(),};
}

}
