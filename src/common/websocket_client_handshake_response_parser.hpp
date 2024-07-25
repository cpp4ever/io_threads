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

#include "io_threads/http_response_parser.hpp" ///< for io_threads::http_response_parser

#include <cstddef> ///< for std::byte
#include <string_view> ///< for std::string_view
#include <system_error> ///< for std::error_code

namespace io_threads
{

class websocket_client_handshake_response_parser final : public http_response_parser
{
public:
   [[nodiscard]] websocket_client_handshake_response_parser() = default;
   websocket_client_handshake_response_parser(websocket_client_handshake_response_parser &&) = delete;
   websocket_client_handshake_response_parser(websocket_client_handshake_response_parser const &) = delete;

   websocket_client_handshake_response_parser &operator = (websocket_client_handshake_response_parser &&) = delete;
   websocket_client_handshake_response_parser &operator = (websocket_client_handshake_response_parser const &) = delete;

   [[nodiscard]] std::string_view const &sec_websocket_accept() const noexcept
   {
      return m_secWebsocketAccept;
   }

private:
   std::string_view m_secWebsocketAccept{};
   std::byte m_validityMask{0};

   [[nodiscard]] std::error_code handle_body(std::string_view const &content, size_t contentLength) override;
   [[nodiscard]] std::error_code handle_header(std::string_view const &headerField, std::string_view const &headerValue) override;
   [[nodiscard]] std::error_code handle_headers_complete() override;
   [[nodiscard]] std::error_code handle_message_begin() override;
   [[nodiscard]] std::error_code handle_message_complete() override;
   [[nodiscard]] std::error_code handle_status(int const statusCode, std::string_view const &status) override;
};

}
