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

#include "common/utility.hpp" ///< for io_threads::to_underlying
#include "common/websocket_error.hpp" ///< for io_threads::websocket_error

#include <system_error> ///< for std::error_category, std::error_code
#include <string> ///< for std::string

namespace io_threads
{

namespace
{

struct websocket_error_category final
{
private:
   class websocket_error_category_impl final : public std::error_category
   {
   public:
      [[nodiscard]] constexpr websocket_error_category_impl() noexcept = default;
      websocket_error_category_impl(websocket_error_category_impl &&) = delete;
      websocket_error_category_impl(websocket_error_category_impl const &) = delete;

      websocket_error_category_impl &operator = (websocket_error_category_impl &&) = delete;
      websocket_error_category_impl &operator = (websocket_error_category_impl const &) = delete;

      [[nodiscard]] const char *name() const noexcept override
      {
         return "websocket";
      }

      [[nodiscard]] std::string message(int const value) const override
      {
         switch (static_cast<websocket_error>(value))
         {
         case websocket_error::handshake_no_connection_header_value:
         return std::string{"HTTP header 'Connection' not found",};

         case websocket_error::handshake_no_sec_websocket_accept_header_value:
         return std::string{"HTTP header 'Sec-WebSocket-Accept' not found",};

         case websocket_error::handshake_no_upgrade_header_value:
         return std::string{"HTTP header 'Upgrade' not found",};

         case websocket_error::handshake_wrong_connection_header_value:
         return std::string{"Wrong HTTP header value 'Connection', expected 'Upgrade'",};

         case websocket_error::handshake_wrong_sec_websocket_accept:
         return std::string{"Failed to match HTTP response header 'Sec-WebSocket-Accept' against HTTP request header 'Sec-WebSocket-Key'",};

         case websocket_error::handshake_wrong_status_code:
         return std::string{"Wrong HTTP status code, expected '101 Switching Protocols'",};

         case websocket_error::handshake_wrong_upgrade_header_value:
         return std::string{"Wrong HTTP header value 'Upgrade', expected 'websocket'",};

         case websocket_error::frame_opcode_not_specified:
         return std::string{"Frame opcode not specified",};

         case websocket_error::frame_not_finalized:
         return std::string{"Frame not finalized",};

         case websocket_error::frame_server_mask_not_supported:
         return std::string{"Server masking not supported",};

         [[unlikely]] default: return std::string{"Unknown error, it must be a bug",};
         }
      }
   };

   static inline websocket_error_category_impl impl{};

public:
   [[nodiscard]] static std::error_category const &instance() noexcept
   {
      return impl;
   }
};

}

[[nodiscard]] std::error_code make_error_code(websocket_error const code) noexcept
{
   return std::error_code{to_underlying(code), websocket_error_category::instance(),};
}

}
