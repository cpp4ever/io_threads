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
#include "common/utility.hpp" ///< for io_threads::unreachable
#include "common/sec_websocket_accept.hpp" ///< for io_threads::make_sec_websocket_accept
#include "common/sec_websocket_key.hpp" ///< for io_threads::build_sec_websocket_key
#include "common/websocket_client_handshake_handler.hpp" ///< for io_threads::websocket_client_handshake_handler
#include "common/websocket_client_session.hpp" ///< for io_threads::websocket_client_session
#include "common/websocket_error.hpp" ///< for io_threads::make_error_code, io_threads::websocket_error
#include "common/websocket_frame_mask.hpp" ///< for io_threads::generate_websocket_frame_mask
#include "io_threads/data_chunk.hpp" ///< for io_threads::data_chunk
#include "io_threads/websocket_client_config.hpp" ///< for io_threads::websocket_client_config

#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <cstddef> ///< for ptrdiff_t, size_t
#include <format> ///< for std::format_to_n
#include <source_location> ///< for std::source_location
#include <string_view> ///< for std::string_view
#include <system_error> ///< for std::error_code

namespace io_threads
{

size_t websocket_client_handshake_handler::build_request(
   websocket_client_session &session,
   data_chunk const &dataChunk,
   websocket_client_config const &config,
   std::string_view const &host
)
{
   assert(nullptr != session.handshakeKey);
   assert(false == config.target().empty());
   assert(false == host.empty());
   assert(nullptr != dataChunk.bytes);
   assert(0 < dataChunk.bytesLength);
   auto const result
   {
      std::format_to_n(
         std::bit_cast<char *>(dataChunk.bytes),
         dataChunk.bytesLength,
         "GET {} HTTP/1.1\r\n"
         "Host:{}\r\n"
         "Upgrade:websocket\r\n"
         "Connection:Upgrade,keep-alive\r\n"
         "Sec-WebSocket-Key:{}\r\n"
         "Sec-WebSocket-Version:13\r\n"
         "Sec-WebSocket-Extensions:permessage-deflate;client_no_context_takeover;server_no_context_takeover,permessage-deflate;client_max_window_bits;server_max_window_bits=15\r\n"
         "\r\n",
         config.target(),
         host,
         build_sec_websocket_key(*session.handshakeKey, m_randomGenerator)
      ),
   };
   if (static_cast<ptrdiff_t>(dataChunk.bytesLength) < result.size) [[unlikely]]
   {
      log_error(
         std::source_location::current(),
         "[wss_client] {} byte send buffer is too small for {} byte handshake",
         dataChunk.bytesLength,
         result.size
      );
      unreachable();
   }
   return result.size;
}

std::error_code websocket_client_handshake_handler::handle_response(
   websocket_client_session &session,
   std::string_view const &handshakeResponse
)
{
   if (auto const errorCode{m_responseParser->parse(handshakeResponse),}; true == bool{errorCode,})
   {
      return errorCode;
   }
   auto const secWebSocketAccept = make_sec_websocket_accept(*session.handshakeKey, m_sha1Context);
   if (
      std::string_view
      {
         std::bit_cast<char const *>(secWebSocketAccept.bytes.data()),
         secWebSocketAccept.bytesLength,
      } != m_responseParser->sec_websocket_accept()
   ) [[unlikely]]
   {
      return make_error_code(websocket_error::handshake_wrong_sec_websocket_accept);
   }
   generate_websocket_frame_mask(session.outboundFrameMask, m_randomGenerator);
   return std::error_code{};
}

}
