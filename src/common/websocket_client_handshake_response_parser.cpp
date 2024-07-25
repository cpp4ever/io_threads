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
#include "common/utility.hpp" ///< for io_threads::to_underlying
#include "common/websocket_client_handshake_response_parser.hpp" ///< for io_threads::websocket_client_handshake_response_parser
#include "common/websocket_error.hpp" ///< for io_threads::make_error_code, io_threads::websocket_error

#if (defined(__linux__))
#  include <strings.h> ///< for strncasecmp
#elif (defined(_WIN32) || defined(_WIN64))
#  include <string.h> ///< for _strnicmp
#endif

#include <cassert> ///< for assert
#include <cstddef> ///< for std::byte
#include <cstdint> ///< for uint16_t
#include <source_location> ///< for std::source_location
#include <string> ///< for std::string
#include <string_view> ///< for std::string_view
#include <system_error> ///< for std::error_category, std::error_code

namespace io_threads
{

std::error_code websocket_client_handshake_response_parser::handle_body(std::string_view const &, size_t const)
{
   assert(false && "Unexpected body");
   return std::error_code{};
}

namespace
{

constexpr std::byte has_connection_header{0x1,};
constexpr std::byte has_sec_websocket_accept_header{0x2,};
constexpr std::byte has_upgrade_header{0x3,};

[[nodiscard]] bool equal_case_insensitive(std::string_view const &lhs, std::string_view const &rhs) noexcept
{
   return (
      true
      && (lhs.size() == rhs.size())
#if (defined(_WIN32) || defined(_WIN64))
      && (0 == _strnicmp(lhs.data(), rhs.data(), lhs.size()))
#else
      && (0 == strncasecmp(lhs.data(), rhs.data(), lhs.size()))
#endif
   );
}

}

std::error_code websocket_client_handshake_response_parser::handle_header(
   std::string_view const &headerField,
   std::string_view const &headerValue
)
{
   assert(false == headerField.empty());
   if (true == equal_case_insensitive("Connection", headerField))
   {
      if (false == equal_case_insensitive("Upgrade", headerValue)) [[unlikely]]
      {
         log_error(
            std::source_location::current(),
            "[wss_client] websocket handshake failed: wrong HTTP header value 'Connection: {}'",
            headerValue
         );
         return make_error_code(websocket_error::handshake_wrong_connection_header_value);
      }
      m_validityMask |= has_connection_header;
   }
   else if (true == equal_case_insensitive("Sec-WebSocket-Accept", headerField))
   {
      m_secWebsocketAccept = headerValue;
      m_validityMask |= has_sec_websocket_accept_header;
   }
   else if (true == equal_case_insensitive("Sec-WebSocket-Extensions", headerField))
   {
      /// TODO: parse permessage-deflate params
   }
   else if (true == equal_case_insensitive("Upgrade", headerField))
   {
      if (false == equal_case_insensitive("websocket", headerValue)) [[unlikely]]
      {
         log_error(
            std::source_location::current(),
            "[wss_client] websocket handshake failed: wrong HTTP header value 'Upgrade: {}'",
            headerValue
         );
         return make_error_code(websocket_error::handshake_wrong_upgrade_header_value);
      }
      m_validityMask |= has_upgrade_header;
   }
   return std::error_code{};
}

std::error_code websocket_client_handshake_response_parser::handle_headers_complete()
{
   if (has_connection_header != (has_connection_header & m_validityMask)) [[unlikely]]
   {
      return make_error_code(websocket_error::handshake_no_connection_header_value);
   }
   if (has_sec_websocket_accept_header != (has_sec_websocket_accept_header & m_validityMask)) [[unlikely]]
   {
      return make_error_code(websocket_error::handshake_no_sec_websocket_accept_header_value);
   }
   if (has_upgrade_header != (has_upgrade_header & m_validityMask)) [[unlikely]]
   {
      return make_error_code(websocket_error::handshake_no_upgrade_header_value);
   }
   return std::error_code{};
}

std::error_code websocket_client_handshake_response_parser::handle_message_begin()
{
   m_validityMask = std::byte{0,};
   m_secWebsocketAccept = std::string_view{"",};
   return std::error_code{};
}

std::error_code websocket_client_handshake_response_parser::handle_message_complete()
{
   return std::error_code{};
}

std::error_code websocket_client_handshake_response_parser::handle_status(int const statusCode, std::string_view const &status)
{
   if (101 == statusCode) [[likely]]
   {
      return std::error_code{};
   }
   log_error(
      std::source_location::current(),
      "[wss_client] websocket handshake failed: wrong HTTP status code '{}', expected '101 Switching Protocols'",
      status
   );
   return make_error_code(websocket_error::handshake_wrong_status_code);
}

}
