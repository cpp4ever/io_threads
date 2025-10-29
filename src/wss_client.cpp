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

#include "common/logger.hpp" ///< for io_threads::log_error
#include "common/utility.hpp" ///< for io_threads::to_underlying, io_threads::unreachable
#include "common/websocket_client_session.hpp" ///< for io_threads::websocket_frame_data, io_threads::websocket_frame_header
#include "common/websocket_error.hpp" ///< for io_threads::make_error_code, io_threads::websocket_error
#include "common/wss_client_context_impl.hpp" ///< for io_threads::wss_client_context::wss_client_context_impl
#include "io_threads/data_chunk.hpp" ///< for io_threads::data_chunk
#include "io_threads/wss_client_context.hpp" ///< for io_threads::wss_client_context
#include "io_threads/wss_client.hpp" ///< for io_threads::wss_client

#if (defined(__linux__))
#  include <endian.h> ///< for be16toh, be64toh
#  define ntohll be64toh
#  define ntohs be16toh
#elif (defined(_WIN32) || defined(_WIN64))
#  include <WinSock2.h> ///< for ntohll, ntohs
#endif

#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <cstddef> ///< for size_t, std::byte
#include <cstdint> ///< for uint16_t, uint32_t, uint64_t, uint8_t
#include <cstring> ///< for std::memcpy
#include <memory> ///< for std::addressof
#include <source_location> ///< for std::source_location
#include <system_error> ///< for std::error_code
#include <utility> ///< for std::move

namespace io_threads
{

wss_client::wss_client(wss_client_context wssClientContext) noexcept :
   super{wssClientContext.m_tlsClientContext,},
   m_wssClientContext{std::move(wssClientContext),}
{}

wss_client::~wss_client() = default;

void wss_client::io_connected()
{
   assert(nullptr == m_websocketClientSession);
   m_websocketClientSession = std::addressof(m_wssClientContext.m_impl->acquire_session());
   super::io_connected();
}

void wss_client::io_disconnected(std::error_code const &errorCode)
{
   super::io_disconnected(errorCode);
   if (nullptr != m_websocketClientSession) [[likely]]
   {
      m_wssClientContext.m_impl->release_session(*m_websocketClientSession);
      m_websocketClientSession = nullptr;
   }
}

void wss_client::ready_to_close()
{
   if (nullptr != m_websocketClientSession) [[likely]]
   {
      m_wssClientContext.m_impl->ready_to_close(*m_websocketClientSession);
      if (nullptr != m_websocketClientSession->outboundFrame)
      {
         ready_to_send();
      }
   }
}

std::error_code wss_client::io_data_decrypted(data_chunk const &dataChunk)
{
   assert(nullptr != m_websocketClientSession);
   if (nullptr == m_websocketClientSession->handshakeKey) [[likely]]
   {
      return io_handle_frame(dataChunk);
   }
   if (
      auto const errorCode{m_wssClientContext.m_impl->handle_handshake_completion(*m_websocketClientSession, dataChunk),};
      true == bool{errorCode,}
   ) [[unlikely]]
   {
      return errorCode;
   }
   assert(nullptr == m_websocketClientSession->handshakeKey);
   ready_to_send();
   return std::error_code{};
}

std::error_code wss_client::io_data_to_encrypt(data_chunk const &dataChunk, size_t &bytesWritten)
{
   assert(nullptr != m_websocketClientSession);
   if (nullptr == m_websocketClientSession->handshakeKey) [[likely]]
   {
      bytesWritten = 0;
      if ((nullptr == m_websocketClientSession->outboundFrame) && (false == m_websocketClientSession->closed))
      {
         if (auto const frame{io_frame_to_send(),}; websocket_frame_type::none != frame.type)
         {
            websocket_frame_header const outboundFrameHeader
            {
               .opcode = static_cast<std::byte>(frame.type),
               .fin = std::byte{1},
            };
            websocket_frame_data const outboundFrame
            {
               .header = outboundFrameHeader,
               .bytesLength = static_cast<uint32_t>(frame.bytesLength),
               .bytes = frame.bytes,
            };
            bytesWritten = m_wssClientContext.m_impl->format_frame(*m_websocketClientSession, dataChunk, outboundFrame);
         }
      }
      if ((0 == bytesWritten) && (nullptr != m_websocketClientSession->outboundFrame))
      {
         bytesWritten = m_wssClientContext.m_impl->format_frame(*m_websocketClientSession, dataChunk, *m_websocketClientSession->outboundFrame);
      }
   }
   else
   {
      bytesWritten = (0 == m_websocketClientSession->handshakeKey->bytesLength)
         ? m_wssClientContext.m_impl->format_handshake_request(*m_websocketClientSession, dataChunk, io_ready_to_handshake(), domain_name())
         : 0
      ;
   }
   return std::error_code{};
}

std::error_code wss_client::io_handle_frame(data_chunk const &dataChunk)
{
   auto *inboundBytes = dataChunk.bytes;
   auto inboundBytesLength = dataChunk.bytesLength;
   auto lastOpcode = websocket_frame_opcode_continuation;
   if (
      true
      && (nullptr != m_websocketClientSession->inboundFrame)
      && (m_websocketClientSession->inboundFrame->frameLength > m_websocketClientSession->inboundFrame->bytesLength)
   )
   {
      assert(0 == m_websocketClientSession->incompleteInboundFrameLength);
      auto &inboundFrame = *m_websocketClientSession->inboundFrame;
#if (not defined(NDEBUG))
      ++inboundFrame.partsCount;
#endif
      auto const inboundFrameTailBytesLength = std::min<size_t>(inboundFrame.frameLength - inboundFrame.bytesLength, inboundBytesLength);
      std::memcpy(inboundFrame.bytes + inboundFrame.bytesLength, inboundBytes, inboundFrameTailBytesLength);
      inboundFrame.bytesLength += static_cast<uint32_t>(inboundFrameTailBytesLength);
      assert(inboundFrame.bytesLength <= inboundFrame.frameLength);
      if (
         true
         && (inboundFrame.bytesLength == inboundFrame.frameLength)
         && ((std::byte{1,}) == inboundFrame.header.fin)
      )
      {
         if (
            auto const errorCode
            {
               m_wssClientContext.m_impl->handle_frame(
                  *m_websocketClientSession,
                  inboundFrame,
                  [this] (auto const dataFrame, bool const finalFrame)
                  {
                     return io_frame_received(dataFrame, finalFrame);
                  }
               ),
            };
            true == bool{errorCode,}
         ) [[unlikely]]
         {
            return errorCode;
         }
         lastOpcode = inboundFrame.header.opcode;
      }
      inboundBytes += inboundFrameTailBytesLength;
      inboundBytesLength -= inboundFrameTailBytesLength;
   }
   while (0 < inboundBytesLength)
   {
      assert(websocket_frame_opcode_connection_close != lastOpcode);
      auto const inboundFrameHeaderLength = std::min(
         sizeof(m_websocketClientSession->incompleteInboundFrame),
         m_websocketClientSession->incompleteInboundFrameLength + inboundBytesLength
      );
      assert(0 < inboundFrameHeaderLength);
      std::memcpy(
         std::addressof(m_websocketClientSession->incompleteInboundFrame[m_websocketClientSession->incompleteInboundFrameLength]),
         inboundBytes,
         inboundFrameHeaderLength - m_websocketClientSession->incompleteInboundFrameLength
      );
      if (1 == inboundFrameHeaderLength)
      {
         assert(1 == inboundBytesLength);
         m_websocketClientSession->incompleteInboundFrameLength = 1;
         break;
      }
      websocket_frame_data inboundFrame
      {
         .header = std::bit_cast<websocket_frame_header>(m_websocketClientSession->incompleteInboundFrame[0]),
#if (not defined(NDEBUG))
         .partsCount = (0 < m_websocketClientSession->incompleteInboundFrameLength) ? uint8_t{2,} : uint8_t{1,},
#endif
      };
      if (std::byte{0,} != (websocket_frame_mask_flag & m_websocketClientSession->incompleteInboundFrame[1])) [[unlikely]]
      {
         return make_error_code(websocket_error::frame_server_mask_not_supported);
      }
      if (websocket_frame_long_payload_flag == (m_websocketClientSession->incompleteInboundFrame[1] & websocket_frame_long_payload_flag))
      {
         if (10 <= inboundFrameHeaderLength) [[likely]]
         {
            uint64_t bytesLength{0,};
            std::memcpy(
               std::addressof(bytesLength),
               std::addressof(m_websocketClientSession->incompleteInboundFrame[2]),
               sizeof(bytesLength)
            );
            inboundFrame.frameLength = static_cast<uint32_t>(ntohll(bytesLength));
            auto const incompleteInboundFrameOffset = 10 - m_websocketClientSession->incompleteInboundFrameLength;
            inboundFrame.bytesLength = std::min(
               inboundFrame.frameLength,
               static_cast<uint32_t>(inboundBytesLength - incompleteInboundFrameOffset)
            );
            inboundFrame.bytes = std::addressof(inboundBytes[incompleteInboundFrameOffset]);
            inboundBytes = inboundFrame.bytes + inboundFrame.bytesLength;
            inboundBytesLength -= inboundFrame.bytesLength + incompleteInboundFrameOffset;
            m_websocketClientSession->incompleteInboundFrameLength = 0;
         }
         else
         {
            m_websocketClientSession->incompleteInboundFrameLength = static_cast<uint8_t>(inboundFrameHeaderLength);
            break;
         }
      }
      else if (websocket_frame_short_payload_flag == (m_websocketClientSession->incompleteInboundFrame[1] & websocket_frame_long_payload_flag))
      {
         if (4 <= inboundFrameHeaderLength) [[likely]]
         {
            uint16_t bytesLength{0,};
            std::memcpy(
               std::addressof(bytesLength),
               std::addressof(m_websocketClientSession->incompleteInboundFrame[2]),
               sizeof(bytesLength)
            );
            inboundFrame.frameLength = ntohs(bytesLength);
            auto const incompleteInboundFrameOffset = 4 - m_websocketClientSession->incompleteInboundFrameLength;
            inboundFrame.bytesLength = std::min(
               inboundFrame.frameLength,
               static_cast<uint32_t>(inboundBytesLength - incompleteInboundFrameOffset)
            );
            inboundFrame.bytes = std::addressof(inboundBytes[incompleteInboundFrameOffset]);
            inboundBytes = inboundFrame.bytes + inboundFrame.bytesLength;
            inboundBytesLength -= inboundFrame.bytesLength + incompleteInboundFrameOffset;
            m_websocketClientSession->incompleteInboundFrameLength = 0;
         }
         else
         {
            m_websocketClientSession->incompleteInboundFrameLength = static_cast<uint8_t>(inboundFrameHeaderLength);
            break;
         }
      }
      else if (2 <= inboundFrameHeaderLength)
      {
         inboundFrame.frameLength = static_cast<uint32_t>(m_websocketClientSession->incompleteInboundFrame[1]);
         auto const incompleteInboundFrameOffset = 2 - m_websocketClientSession->incompleteInboundFrameLength;
         inboundFrame.bytesLength = std::min(
            inboundFrame.frameLength,
            static_cast<uint32_t>(inboundBytesLength - incompleteInboundFrameOffset)
         );
         inboundFrame.bytes = std::addressof(inboundBytes[incompleteInboundFrameOffset]);
         inboundBytes = inboundFrame.bytes + inboundFrame.bytesLength;
         inboundBytesLength -= inboundFrame.bytesLength + incompleteInboundFrameOffset;
         m_websocketClientSession->incompleteInboundFrameLength = 0;
      }
      else
      {
         m_websocketClientSession->incompleteInboundFrameLength = static_cast<uint8_t>(inboundFrameHeaderLength);
         break;
      }
      assert(inboundFrame.bytesLength <= inboundFrame.frameLength);
      if (
         auto const errorCode
         {
            m_wssClientContext.m_impl->handle_frame(
               *m_websocketClientSession,
               inboundFrame,
               [this] (auto const dataFrame, bool const finalFrame)
               {
                  return io_frame_received(dataFrame, finalFrame);
               }
            ),
         };
         true == bool{errorCode,}
      ) [[unlikely]]
      {
         return errorCode;
      }
      lastOpcode = inboundFrame.header.opcode;
   }
   if (
      true
      && (websocket_frame_opcode_connection_close == lastOpcode)
      && (nullptr == m_websocketClientSession->outboundFrame)
   )
   {
      ready_to_disconnect();
   }
   else if (nullptr != m_websocketClientSession->outboundFrame)
   {
      ready_to_send();
   }
   return std::error_code{};
}

}
