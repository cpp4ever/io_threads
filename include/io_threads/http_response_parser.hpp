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

#include <llhttp.h> ///< for llhttp_t, llhttp_settings_t

#include <cstddef> ///< for size_t
#include <memory> ///< for std::unique_ptr
#include <string_view> ///< for std::string_view
#include <system_error> ///< for std::error_code

namespace io_threads
{

class http_response_parser
{
public:
   [[nodiscard]] http_response_parser();
   http_response_parser(http_response_parser &&) = delete;
   http_response_parser(http_response_parser const &) = delete;

   http_response_parser &operator = (http_response_parser &&) = delete;
   http_response_parser &operator = (http_response_parser const &) = delete;

   [[nodiscard]] std::error_code parse(std::string_view const &httpResponse);

private:
   struct http_response_parser_context;

   std::unique_ptr<llhttp_t> const m_llhttp;
   size_t m_contentLength{0,};
   std::unique_ptr<llhttp_settings_t> const m_llhttpSettings;

   [[nodiscard]] virtual std::error_code handle_body(std::string_view const &content, size_t contentLength) = 0;
   [[nodiscard]] virtual std::error_code handle_header(std::string_view const &headerField, std::string_view const &headerValue) = 0;
   [[nodiscard]] virtual std::error_code handle_headers_complete() = 0;
   [[nodiscard]] virtual std::error_code handle_message_begin() = 0;
   [[nodiscard]] virtual std::error_code handle_message_complete() = 0;
   [[nodiscard]] virtual std::error_code handle_status(int statusCode, std::string_view const &status) = 0;

   [[nodiscard]] static int on_body(llhttp_t *llhttp, char const *at, size_t length);
   [[nodiscard]] static int on_header_field(llhttp_t *llhttp, char const *at, size_t length);
   [[nodiscard]] static int on_header_value(llhttp_t *llhttp, char const *at, size_t length);
   [[nodiscard]] static int on_headers_complete(llhttp_t *llhttp);
   [[nodiscard]] static int on_message_begin(llhttp_t *llhttp);
   [[nodiscard]] static int on_message_complete(llhttp_t *llhttp);
   [[nodiscard]] static int on_status(llhttp_t *llhttp, char const *at, size_t length);
   [[nodiscard]] static int on_status_complete(llhttp_t *llhttp);
};

}
