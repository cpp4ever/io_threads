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
#include "common/object_pool.hpp" ///< for io_threads::object_pool
#include "common/utility.hpp" ///< for io_threads::unreachable
#include "io_threads/data_chunk.hpp" ///< for io_threads::data_chunk
#include "io_threads/tcp_client_thread.hpp" ///< for io_threads::tcp_client_thread
#include "io_threads/tls_client_context.hpp" ///< for io_threads::tls_client_context
#include "io_threads/websocket_client_context.hpp" ///< for io_threads::websocket_client_context
#include "io_threads/wss_client.hpp" ///< for io_threads::websocket_client_context::wss_client

#include <libbase64.h> ///< for base64_state, base64_stream_encode, base64_stream_encode_final, base64_stream_encode_init
/// for
///   HPE_OK,
///   HPE_PAUSED_UPGRADE,
///   HPE_USER,
///   llhttp_errno_name,
///   llhttp_errno_t,
///   llhttp_execute,
///   llhttp_get_error_reason,
///   llhttp_get_status_code,
///   llhttp_init,
///   llhttp_reset,
///   llhttp_settings_init,
///   llhttp_settings_t,
///   llhttp_t,
///   llhttp_type_t
#include <llhttp.h>
#include <sha1.h> ///< for SHA1_CTX, SHA1Final, SHA1Init, SHA1Update
#if (defined(_WIN32) || defined(_WIN64))
#  include <WinSock2.h> ///< for _strnicmp, htonll, htons, ntohll, ntohs
#endif

#include <algorithm> ///< for std::generate_n
#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <climits> ///< for CHAR_BIT, UCHAR_MAX
#include <cstddef> ///< for ptrdiff_t, size_t, std::byte
#include <cstdint> ///< for uint16_t, uint32_t, uint64_t, uint8_t
#include <format> ///< for std::format_to_n
#include <memory> ///< for std::addressof
#include <random> ///< for std::default_random_engine, std::random_device, std::uniform_int_distribution
#include <source_location> ///< for std::source_location
#include <string> ///< for std::string
#include <string_view> ///< for std::string_view
#include <system_error> ///< for std::error_category, std::error_code

namespace io_threads
{

namespace
{

class llhttp_error_category final : public std::error_category
{
public:
   llhttp_error_category(llhttp_error_category &&) = delete;
   llhttp_error_category(llhttp_error_category const &) = delete;

   llhttp_error_category &operator = (llhttp_error_category &&) = delete;
   llhttp_error_category &operator = (llhttp_error_category const &) = delete;

   const char *name() const noexcept override
   {
      return "llhttp";
   }

   std::string message(int errorCode) const override
   {
      return llhttp_errno_name(static_cast<llhttp_errno_t>(errorCode));
   }

   static llhttp_error_category &instance()
   {
      static llhttp_error_category errorCategory{};
      return errorCategory;
   }

private:
   llhttp_error_category() = default;
};

std::error_code make_llhttp_error_code(llhttp_errno_t const errorCode)
{
   return std::error_code{to_underlying(errorCode), llhttp_error_category::instance()};
}

}

constexpr uint16_t HTTP_RESPONSE_HEADER_CONNECTION = 0x1;
constexpr uint16_t HTTP_RESPONSE_HEADER_SEC_WEBSOCKET_ACCEPT = 0x2;
constexpr uint16_t HTTP_RESPONSE_HEADER_SEC_WEBSOCKET_EXTENSIONS = 0x4;
constexpr uint16_t HTTP_RESPONSE_HEADER_UPGRADE = 0x8;
constexpr uint16_t HTTP_RESPONSE_HEADERS_VALID =
   HTTP_RESPONSE_HEADER_CONNECTION |
   HTTP_RESPONSE_HEADER_SEC_WEBSOCKET_ACCEPT |
   HTTP_RESPONSE_HEADER_SEC_WEBSOCKET_EXTENSIONS |
   HTTP_RESPONSE_HEADER_UPGRADE
;

struct websocket_client_session final
{
   std::byte *outboundBuffer = nullptr;
   uint32_t mask = 0;
   uint16_t handshakeHeadersState = 0;
   bool handshake = true;
   std::string_view handshakeHeaderName = {};
   std::string_view handshakeKey = {};
};

[[nodiscard]] bool equal_case_insensitive(std::string_view const lhs, std::string_view const rhs) noexcept
{
   return (lhs.size() == rhs.size()) && (0 == _strnicmp(lhs.data(), rhs.data(), lhs.size()));
}

class websocket_client_context::websocket_client_context_impl final
{
public:
   websocket_client_context_impl() = delete;
   websocket_client_context_impl(websocket_client_context_impl &&) = delete;
   websocket_client_context_impl(websocket_client_context_impl const &) = delete;

   [[nodiscard]] websocket_client_context_impl(
      size_t const inboundBufferListCapacity,
      size_t const inboundBufferCapacity,
      size_t const outboundBufferListCapacity,
      size_t const outboundBufferCapacity
   ) :
      m_inboundMessages(inboundBufferListCapacity, inboundBufferCapacity),
      m_sessions(outboundBufferListCapacity, sizeof(websocket_client_session) + outboundBufferCapacity)
   {
      llhttp_settings_init(std::addressof(m_httpParserSettings));
      m_httpParserSettings.on_status_complete = on_handshake_status_complete;
      m_httpParserSettings.on_header_field = on_handshake_header_field;
      m_httpParserSettings.on_header_value = on_handshake_header_value;
      m_httpParserSettings.on_message_complete = on_handshake_complete;
      llhttp_init(std::addressof(m_httpParser), llhttp_type_t::HTTP_RESPONSE, std::addressof(m_httpParserSettings));
      m_randomEngine.seed(std::random_device{}());
      base64_stream_encode_init(std::addressof(m_base64State), 0);
   }

   websocket_client_context_impl &operator = (websocket_client_context_impl &&) = delete;
   websocket_client_context_impl &operator = (websocket_client_context_impl const &) = delete;

   [[nodiscard]] websocket_client_session &acquire_session()
   {
      auto &session = m_sessions.pop();
      session.outboundBuffer = std::bit_cast<std::byte *>(std::addressof(session) + 1);
      auto *mask = std::bit_cast<char *>(std::addressof(session.mask));
      auto maskDistribution = std::uniform_int_distribution{0x01, UCHAR_MAX};
      for (size_t maskIndex = 0; maskIndex < sizeof(session.mask); ++maskIndex)
      {
         mask[maskIndex] = static_cast<char>(maskDistribution(m_randomEngine));
      }
      return session;
   }

   [[nodiscard]] std::string_view generate_handshake_key(websocket_client_session &session)
   {
      assert(nullptr != session.outboundBuffer);
      assert(true == session.handshake);
      char key[16] = {};
      auto keyDistribution = std::uniform_int_distribution{0x01, UCHAR_MAX};
      std::generate_n(
         std::addressof(key[0]),
         sizeof(key),
         [this, &keyDistribution] ()
         {
            return static_cast<char>(keyDistribution(m_randomEngine));
         }
      );
      size_t bytesLength = m_sessions.object_size() - sizeof(websocket_client_session);
      base64_stream_encode(
         std::addressof(m_base64State),
         key,
         sizeof(key),
         std::bit_cast<char *>(session.outboundBuffer),
         std::addressof(bytesLength)
      );
      size_t trailingBytesLength = 0;
      base64_stream_encode_final(
         std::addressof(m_base64State),
         std::bit_cast<char *>(session.outboundBuffer + bytesLength),
         std::addressof(trailingBytesLength)
      );
      session.handshakeKey = std::string_view{std::bit_cast<char *>(session.outboundBuffer), bytesLength + trailingBytesLength};
      return session.handshakeKey;
   }

   [[nodiscard]] std::error_code handle_handshake_completion(
      websocket_client_session &session,
      data_chunk const dataChunk
   )
   {
      std::error_code errorCode = {};
      m_httpParser.data = std::addressof(session);
      if (
         auto const returnCode = llhttp_execute(
            std::addressof(m_httpParser),
            std::bit_cast<char const *>(dataChunk.bytes),
            dataChunk.bytesLength
         );
         HPE_PAUSED_UPGRADE != returnCode
      ) [[unlikely]]
      {
         log_error(
            std::source_location::current(),
            "[wss_client] websocket handshake failed: ({}) - {}",
            std::string_view{llhttp_errno_name(returnCode)},
            std::string_view{llhttp_get_error_reason(std::addressof(m_httpParser))}
         );
         errorCode = make_llhttp_error_code(returnCode);
      }
      llhttp_reset(std::addressof(m_httpParser));
      return errorCode;
   }

   void release_session(websocket_client_session &session)
   {
      m_sessions.push(session);
   }

private:
   object_pool<std::byte> m_inboundMessages;
   object_pool<websocket_client_session> m_sessions;
   llhttp_t m_httpParser = {};
   std::default_random_engine m_randomEngine = {};
   base64_state m_base64State = {};
   llhttp_settings_t m_httpParserSettings = {};

   [[nodiscard]] static int on_handshake_complete(llhttp_t *httpParser)
   {
      assert(nullptr != httpParser->data);
      auto &session = *std::bit_cast<websocket_client_session *>(httpParser->data);
      assert(true == session.handshake);
      if (HTTP_RESPONSE_HEADERS_VALID == (HTTP_RESPONSE_HEADERS_VALID & session.handshakeHeadersState)) [[likely]]
      {
         session.handshake = false;
         return HPE_OK;
      }
      log_error(
         std::source_location::current(),
         "[wss_client] websocket handshake failed: missing headers"
      );
      return HPE_USER;
   }

   [[nodiscard]] static int on_handshake_header_field(llhttp_t *httpParser, const char *at, size_t const length)
   {
      assert(nullptr != httpParser->data);
      auto &session = *std::bit_cast<websocket_client_session *>(httpParser->data);
      assert(true == session.handshake);
      assert(true == session.handshakeHeaderName.empty());
      session.handshakeHeaderName = std::string_view{at, length};
      return HPE_OK;
   }

   [[nodiscard]] static int on_handshake_header_value(llhttp_t *httpParser, const char *at, size_t const length)
   {
      assert(nullptr != httpParser->data);
      auto &session = *std::bit_cast<websocket_client_session *>(httpParser->data);
      assert(true == session.handshake);
      assert(false == session.handshakeHeaderName.empty());
      if (true == equal_case_insensitive("Upgrade", session.handshakeHeaderName))
      {
         if (false == equal_case_insensitive("websocket", std::string_view{at, length})) [[unlikely]]
         {
            log_error(
               std::source_location::current(),
               R"raw([wss_client] websocket handshake failed: bad header value "Upgrade":"{}")raw",
               std::string_view{at, length}
            );
            return HPE_USER;
         }
         session.handshakeHeadersState |= HTTP_RESPONSE_HEADER_UPGRADE;
      }
      else if (true == equal_case_insensitive("Connection", session.handshakeHeaderName))
      {
         if (false == equal_case_insensitive("Upgrade", std::string_view{at, length})) [[unlikely]]
         {
            log_error(
               std::source_location::current(),
               R"raw([wss_client] websocket handshake failed: bad header value "Connection":"{}")raw",
               std::string_view{at, length}
            );
            return HPE_USER;
         }
         session.handshakeHeadersState |= HTTP_RESPONSE_HEADER_CONNECTION;
      }
      else if (true == equal_case_insensitive("Sec-WebSocket-Accept", session.handshakeHeaderName))
      {
         if (false == validate_handshake_key(session, std::string_view{at, length})) [[unlikely]]
         {
            log_error(
               std::source_location::current(),
               "[wss_client] websocket handshake failed: key does not match"
            );
            return HPE_USER;
         }
         session.handshakeHeadersState |= HTTP_RESPONSE_HEADER_SEC_WEBSOCKET_ACCEPT;
      }
      else if (true == equal_case_insensitive("Sec-WebSocket-Extensions", session.handshakeHeaderName))
      {
         /// TODO: parse permessage-deflate params
         session.handshakeHeadersState |= HTTP_RESPONSE_HEADER_SEC_WEBSOCKET_EXTENSIONS;
      }
      session.handshakeHeaderName = {};
      return HPE_OK;
   }

   [[nodiscard]] static int on_handshake_status_complete(llhttp_t *httpParser)
   {
      assert(nullptr != httpParser->data);
      auto &session = *std::bit_cast<websocket_client_session *>(httpParser->data);
      assert(true == session.handshake);
      auto const httpStatusCode = llhttp_get_status_code(httpParser);
      if (101 == httpStatusCode) [[likely]]
      {
         return HPE_OK;
      }
      log_error(
         std::source_location::current(),
         "[wss_client] websocket handshake failed: http status expected 101 but actual is {}",
         httpStatusCode
      );
      return HPE_USER;
   }

   [[nodiscard]] static bool validate_handshake_key(websocket_client_session &session, std::string_view const &value)
   {
      auto const handshakeKey = session.handshakeKey;
      assert(false == handshakeKey.empty());
      constexpr auto handshakeUuid = std::string_view{"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"};
      SHA1_CTX sha1Conext = {};
      SHA1Init(std::addressof(sha1Conext));
      SHA1Update(std::addressof(sha1Conext), std::bit_cast<uint8_t const *>(handshakeKey.data()), handshakeKey.size());
      SHA1Update(std::addressof(sha1Conext), std::bit_cast<uint8_t const *>(handshakeUuid.data()), handshakeUuid.size());
      uint8_t sha1Digest[20] = {};
      SHA1Final(sha1Digest, std::addressof(sha1Conext));
      char base64Hash[sizeof(sha1Digest) * 2] = {};
      size_t base64HashSize = sizeof(base64Hash);
      base64_encode(std::bit_cast<char const *>(std::addressof(sha1Digest)), sizeof(sha1Digest), base64Hash, std::addressof(base64HashSize), 0);
      return value == std::string_view{base64Hash, base64HashSize};
   }
};

websocket_client_context::websocket_client_context(websocket_client_context &&rhs) noexcept = default;
websocket_client_context::websocket_client_context(websocket_client_context const &rhs) noexcept = default;

websocket_client_context::websocket_client_context(
   size_t const inboundBufferListCapacity,
   size_t const inboundBufferCapacity,
   size_t const outboundBufferListCapacity,
   size_t const outboundBufferCapacity
) :
   m_impl(
      std::make_unique<websocket_client_context_impl>(
         inboundBufferListCapacity,
         inboundBufferCapacity,
         outboundBufferListCapacity,
         outboundBufferCapacity
      )
   )
{
   assert(nullptr != m_impl);
}

websocket_client_context::~websocket_client_context() = default;

websocket_client_context &websocket_client_context::operator = (websocket_client_context &&rhs) noexcept = default;
websocket_client_context &websocket_client_context::operator = (websocket_client_context const &rhs) = default;

websocket_client_context::wss_client::wss_client(
   tcp_client_thread const &tcpClientThread,
   tls_client_context const &tlsClientContext,
   websocket_client_context const &websocketClientContext
) :
   super(tcpClientThread, tlsClientContext),
   m_context(websocketClientContext.m_impl)
{
   assert(nullptr != m_context);
}

websocket_client_context::wss_client::~wss_client()
{
   assert(nullptr == m_session);
   assert(nullptr != m_context);
}

void websocket_client_context::wss_client::io_connected()
{
   assert(nullptr == m_session);
   assert(nullptr != m_context);
   m_session = std::addressof(m_context->acquire_session());
   super::io_connected();
}

void websocket_client_context::wss_client::io_disconnected(std::error_code const errorCode)
{
   super::io_disconnected(errorCode);
   assert(nullptr != m_context);
   if (nullptr != m_session)
   {
      m_context->release_session(*m_session);
      m_session = nullptr;
   }
}

constexpr auto websocket_frame_fin_flag = std::byte{1 << 7};
constexpr auto websocket_frame_rsv1_flag = std::byte{1 << 6};
constexpr auto websocket_frame_rsv2_flag = std::byte{1 << 5};
constexpr auto websocket_frame_rsv3_flag = std::byte{1 << 4};
constexpr auto websocket_frame_mask_flag = std::byte{1 << 7};
constexpr size_t websocket_frame_max_tiny_payload_size = 125;
constexpr auto websocket_frame_short_payload_flag = std::byte{126};
constexpr size_t websocket_frame_max_short_payload_size = 64 * 1024;
constexpr auto websocket_frame_long_payload_flag = std::byte{127};

std::error_code websocket_client_context::wss_client::io_data_decrypted(data_chunk const dataChunk)
{
   assert(nullptr != m_session);
   assert(nullptr != m_context);
   if (true == m_session->handshake) [[unlikely]]
   {
      if (auto const errorCode = m_context->handle_handshake_completion(*m_session, dataChunk); errorCode) [[unlikely]]
      {
         return errorCode;
      }
      assert(false == m_session->handshake);
      ready_to_send();
      return {};
   }
   assert(websocket_frame_fin_flag == (websocket_frame_fin_flag & dataChunk.bytes[0]));
   websocket_frame frame =
   {
      .type = static_cast<websocket_frame_type>(dataChunk.bytes[0] & std::byte{0xF}),
      .final = true,
   };
   assert(std::byte{0} == (websocket_frame_mask_flag & dataChunk.bytes[1]));
   if (websocket_frame_long_payload_flag == (dataChunk.bytes[1] & websocket_frame_long_payload_flag))
   {
      uint64_t bytesLength = 0;
      std::memcpy(std::addressof(bytesLength), std::addressof(dataChunk.bytes[2]), sizeof(bytesLength));
      frame.bytes = std::addressof(dataChunk.bytes[10]);
      frame.bytesLength = ntohll(bytesLength);
   }
   else if (websocket_frame_short_payload_flag == (dataChunk.bytes[1] & websocket_frame_long_payload_flag))
   {
      uint16_t bytesLength = 0;
      std::memcpy(std::addressof(bytesLength), std::addressof(dataChunk.bytes[2]), sizeof(bytesLength));
      frame.bytes = std::addressof(dataChunk.bytes[4]);
      frame.bytesLength = ntohs(bytesLength);
   }
   else
   {
      frame.bytes = std::addressof(dataChunk.bytes[2]);
      frame.bytesLength = static_cast<size_t>(dataChunk.bytes[1]);
   }
   if (websocket_frame_rsv1_flag == (websocket_frame_rsv1_flag & dataChunk.bytes[0]))
   {
      /// TODO: deflate
      assert(false);
   }
   return io_frame_received(frame);
}

std::error_code websocket_client_context::wss_client::io_data_to_encrypt(data_chunk const dataChunk, size_t &bytesWritten)
{
   assert(nullptr != m_session);
   assert(nullptr != m_context);
   if (true == m_session->handshake) [[unlikely]]
   {
      if (true == m_session->handshakeKey.empty())
      {
         auto const result = std::format_to_n(
            std::bit_cast<char *>(dataChunk.bytes),
            dataChunk.bytesLength,
            "GET / HTTP/1.1\r\n"
            "Host:{}\r\n"
            "Upgrade:websocket\r\n"
            "Connection:Upgrade,keep-alive\r\n"
            "Sec-WebSocket-Key:{}\r\n"
            "Sec-WebSocket-Version:13\r\n"
            "Sec-WebSocket-Extensions:permessage-deflate;client_no_context_takeover;server_no_context_takeover,permessage-deflate;client_max_window_bits=15;server_max_window_bits=15\r\n"
            "\r\n",
            domain_name(),
            m_context->generate_handshake_key(*m_session)
         );
         if (static_cast<ptrdiff_t>(dataChunk.bytesLength) < result.size) [[unlikely]]
         {
            log_error(
               std::source_location::current(),
               "[wss_client] send buffer ({} bytes) too small for websocket handshake ({} bytes)",
               dataChunk.bytesLength,
               result.size
            );
            unreachable();
         }
         bytesWritten = result.size;
      }
      else
      {
         bytesWritten = 0;
      }
   }
   else
   {
      auto outboundFrame = io_frame_to_send();
      if ((0 < outboundFrame.bytesLength) || (websocket_frame_type::connection_close == outboundFrame.type))
      {
         dataChunk.bytes[0] = websocket_frame_fin_flag | std::byte{to_underlying(outboundFrame.type)};
         if (websocket_frame_max_tiny_payload_size >= outboundFrame.bytesLength)
         {
            auto const tinyBytesLength = static_cast<uint8_t>(outboundFrame.bytesLength);
            dataChunk.bytes[1] = websocket_frame_mask_flag | std::byte{tinyBytesLength};
            bytesWritten = 2;
         }
         else if (websocket_frame_max_short_payload_size >= outboundFrame.bytesLength)
         {
            dataChunk.bytes[1] = websocket_frame_mask_flag | websocket_frame_short_payload_flag;
            auto const shortBytesLength = htons(static_cast<uint16_t>(outboundFrame.bytesLength));
            std::memcpy(std::addressof(dataChunk.bytes[2]), std::addressof(shortBytesLength), sizeof(shortBytesLength));
            bytesWritten = 4;
         }
         else
         {
            dataChunk.bytes[1] = websocket_frame_mask_flag | websocket_frame_long_payload_flag;
            auto const longBytesLength = htonll(static_cast<uint64_t>(outboundFrame.bytesLength));
            std::memcpy(std::addressof(dataChunk.bytes[2]), std::addressof(longBytesLength), sizeof(longBytesLength));
            bytesWritten = 10;
         }
         std::memcpy(std::addressof(dataChunk.bytes[bytesWritten]), std::addressof(m_session->mask), sizeof(m_session->mask));
         bytesWritten += sizeof(m_session->mask);
         auto *mask = std::bit_cast<std::byte *>(std::addressof(m_session->mask));
         while (sizeof(m_session->mask) < outboundFrame.bytesLength)
         {
            for (size_t maskIndex = 0; sizeof(m_session->mask) > maskIndex; ++maskIndex, ++bytesWritten)
            {
               dataChunk.bytes[bytesWritten] = outboundFrame.bytes[maskIndex] ^ mask[maskIndex];
            }
            outboundFrame.bytes += sizeof(m_session->mask);
            outboundFrame.bytesLength -= sizeof(m_session->mask);
         }
         for (size_t maskIndex = 0; maskIndex < outboundFrame.bytesLength; ++maskIndex, ++bytesWritten)
         {
            dataChunk.bytes[bytesWritten] = outboundFrame.bytes[maskIndex] ^ mask[maskIndex];
         }
         auto const lowestBit = m_session->mask & 0x1;
         m_session->mask = (m_session->mask >> 1) | (lowestBit << (sizeof(m_session->mask) * CHAR_BIT - 1));
      }
      else
      {
         bytesWritten = 0;
      }
   }
   return {};
}

}
