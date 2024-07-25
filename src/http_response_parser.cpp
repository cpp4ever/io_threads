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
#include "io_threads/http_response_parser.hpp" ///< for io_threads::http_response_parser

/// for
///   llhttp_errno,
///   llhttp_errno_name,
///   llhttp_execute,
///   llhttp_get_errno,
///   llhttp_get_error_reason,
///   llhttp_init,
///   llhttp_reset,
///   llhttp_resume_after_upgrade,
///   llhttp_settings_init,
///   llhttp_settings_t,
///   llhttp_t,
///   llhttp_type_t
#include <llhttp.h>

#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <cstddef> ///< for size_t
#include <memory> ///< for std::addressof
#include <source_location> ///< for std::source_location
#include <string> ///< for std::string
#include <string_view> ///< for std::string_view
#include <system_error> ///< for std::error_category, std::error_code

namespace io_threads
{

http_response_parser::http_response_parser()
{
   m_llhttp = std::make_unique<llhttp_t>();
   m_llhttpSettings = std::make_unique<llhttp_settings_t>();
   llhttp_settings_init(m_llhttpSettings.get());
   m_llhttpSettings->on_message_begin = on_message_begin;
   m_llhttpSettings->on_status = on_status;
   m_llhttpSettings->on_header_field = on_header_field;
   m_llhttpSettings->on_header_value = on_header_value;
   m_llhttpSettings->on_headers_complete = on_headers_complete;
   m_llhttpSettings->on_body = on_body;
   m_llhttpSettings->on_message_complete = on_message_complete;
   m_llhttpSettings->on_status_complete = on_status_complete;
   llhttp_init(m_llhttp.get(), llhttp_type_t::HTTP_RESPONSE, m_llhttpSettings.get());
   m_llhttp->data = this;
}

struct http_response_parser::http_response_parser_context final
{
   http_response_parser &parser;
   std::string_view tmpString{"",};
   std::error_code errorCode{};
};

namespace
{

struct llhttp_error_category final
{
private:
   class llhttp_error_category_impl final : public std::error_category
   {
   public:
      [[nodiscard]] constexpr llhttp_error_category_impl() noexcept = default;
      llhttp_error_category_impl(llhttp_error_category_impl &&) = delete;
      llhttp_error_category_impl(llhttp_error_category_impl const &) = delete;

      llhttp_error_category_impl &operator = (llhttp_error_category_impl &&) = delete;
      llhttp_error_category_impl &operator = (llhttp_error_category_impl const &) = delete;

      [[nodiscard]] const char *name() const noexcept override
      {
         return "http";
      }

      [[nodiscard]] std::string message(int const value) const override
      {
         return std::string{llhttp_errno_name(static_cast<llhttp_errno_t>(value)),};
      }
   };

   static inline llhttp_error_category_impl impl{};

public:
   static std::error_category const &instance() noexcept
   {
      return impl;
   }
};

std::error_code make_error_code(llhttp_errno_t const value)
{
   return std::error_code{static_cast<int>(to_underlying(value)), llhttp_error_category::instance(),};
}

}

std::error_code http_response_parser::parse(std::string_view const &httpResponse)
{
   assert(false == httpResponse.empty());
   assert(llhttp_errno::HPE_OK == llhttp_get_errno(m_llhttp.get()));
   http_response_parser_context httpResponseParserContext
   {
      .parser = *this,
   };
   m_llhttp->data = std::addressof(httpResponseParserContext);
   auto const returnCode
   {
      llhttp_execute(
         m_llhttp.get(),
         httpResponse.data(),
         httpResponse.size()
      ),
   };
   m_llhttp->data = nullptr;
   switch (returnCode)
   {
   case llhttp_errno::HPE_OK:
   {
      assert(false == (bool{httpResponseParserContext.errorCode,}));
   }
   return httpResponseParserContext.errorCode;

   case llhttp_errno::HPE_PAUSED_UPGRADE: [[fallthrough]];
   case llhttp_errno::HPE_PAUSED_H2_UPGRADE:
   {
      assert(false == (bool{httpResponseParserContext.errorCode,}));
      llhttp_resume_after_upgrade(m_llhttp.get());
   }
   return httpResponseParserContext.errorCode;

   case llhttp_errno::HPE_PAUSED:
   {
      assert(true == (bool{httpResponseParserContext.errorCode,}));
      llhttp_reset(m_llhttp.get());
      m_contentLength = 0;
   }
   return httpResponseParserContext.errorCode;

   default:
   {
      assert(false == (bool{httpResponseParserContext.errorCode,}));
      log_error(
         std::source_location::current(),
         "[http_response_parser] HTTP parse error: ({}) - {}",
         std::string_view{llhttp_errno_name(returnCode),},
         std::string_view{llhttp_get_error_reason(m_llhttp.get()),}
      );
      llhttp_reset(m_llhttp.get());
      m_contentLength = 0;
   }
   }
   return make_error_code(returnCode);
}

int http_response_parser::on_body(llhttp_t *llhttp, char const *at, size_t const length)
{
   assert(nullptr != llhttp);
   assert(nullptr != llhttp->data);
   assert(nullptr != at);
   assert(0 < length);
   auto &httpResponseParserContext{*std::bit_cast<http_response_parser_context *>(llhttp->data),};
   assert(true == httpResponseParserContext.tmpString.empty());
   assert(false == (bool{httpResponseParserContext.errorCode,}));
   httpResponseParserContext.errorCode = httpResponseParserContext.parser.handle_body(
      std::string_view{at, length,},
      httpResponseParserContext.parser.m_contentLength
   );
   return httpResponseParserContext.errorCode ? llhttp_errno::HPE_PAUSED : llhttp_errno::HPE_OK;
}

int http_response_parser::on_header_field(llhttp_t *llhttp, char const *at, size_t const length)
{
   assert(nullptr != llhttp);
   assert(nullptr != llhttp->data);
   assert(nullptr != at);
   assert(0 < length);
   auto &httpResponseParserContext{*std::bit_cast<http_response_parser_context *>(llhttp->data),};
   assert(true == httpResponseParserContext.tmpString.empty());
   assert(false == (bool{httpResponseParserContext.errorCode,}));
   httpResponseParserContext.tmpString = std::string_view{at, length,};
   return llhttp_errno::HPE_OK;
}

int http_response_parser::on_header_value(llhttp_t *llhttp, char const *at, size_t const length)
{
   assert(nullptr != llhttp);
   assert(nullptr != llhttp->data);
   assert(nullptr != at);
   assert(0 < length);
   auto &httpResponseParserContext{*std::bit_cast<http_response_parser_context *>(llhttp->data),};
   assert(false == httpResponseParserContext.tmpString.empty());
   assert(false == (bool{httpResponseParserContext.errorCode,}));
   httpResponseParserContext.errorCode = httpResponseParserContext.parser.handle_header(
      httpResponseParserContext.tmpString,
      std::string_view{at, length,}
   );
   httpResponseParserContext.tmpString = std::string_view{"",};
   return httpResponseParserContext.errorCode ? llhttp_errno::HPE_PAUSED : llhttp_errno::HPE_OK;
}

int http_response_parser::on_headers_complete(llhttp_t *llhttp)
{
   assert(nullptr != llhttp);
   assert(nullptr != llhttp->data);
   auto &httpResponseParserContext{*std::bit_cast<http_response_parser_context *>(llhttp->data),};
   assert(true == httpResponseParserContext.tmpString.empty());
   assert(false == (bool{httpResponseParserContext.errorCode,}));
   httpResponseParserContext.parser.m_contentLength = static_cast<size_t>(llhttp->content_length);
   httpResponseParserContext.errorCode = httpResponseParserContext.parser.handle_headers_complete();
   return httpResponseParserContext.errorCode ? llhttp_errno::HPE_PAUSED : llhttp_errno::HPE_OK;
}

int http_response_parser::on_message_begin(llhttp_t *llhttp)
{
   assert(nullptr != llhttp);
   assert(nullptr != llhttp->data);
   auto &httpResponseParserContext{*std::bit_cast<http_response_parser_context *>(llhttp->data),};
   assert(true == httpResponseParserContext.tmpString.empty());
   assert(false == (bool{httpResponseParserContext.errorCode,}));
   httpResponseParserContext.errorCode = httpResponseParserContext.parser.handle_message_begin();
   return httpResponseParserContext.errorCode ? llhttp_errno::HPE_PAUSED : llhttp_errno::HPE_OK;
}

int http_response_parser::on_message_complete(llhttp_t *llhttp)
{
   assert(nullptr != llhttp);
   assert(nullptr != llhttp->data);
   auto &httpResponseParserContext{*std::bit_cast<http_response_parser_context *>(llhttp->data),};
   assert(true == httpResponseParserContext.tmpString.empty());
   assert(false == (bool{httpResponseParserContext.errorCode,}));
   httpResponseParserContext.errorCode = httpResponseParserContext.parser.handle_message_complete();
   httpResponseParserContext.parser.m_contentLength = 0;
   return httpResponseParserContext.errorCode ? llhttp_errno::HPE_PAUSED : llhttp_errno::HPE_OK;
}

int http_response_parser::on_status(llhttp_t *llhttp, char const *at, size_t const length)
{
   assert(nullptr != llhttp);
   assert(nullptr != llhttp->data);
   assert(nullptr != at);
   assert(0 < length);
   auto &httpResponseParserContext{*std::bit_cast<http_response_parser_context *>(llhttp->data),};
   assert(true == httpResponseParserContext.tmpString.empty());
   assert(false == (bool{httpResponseParserContext.errorCode,}));
   httpResponseParserContext.tmpString = std::string_view{at, length,};
   return llhttp_errno::HPE_OK;
}

int http_response_parser::on_status_complete(llhttp_t *llhttp)
{
   assert(nullptr != llhttp);
   assert(nullptr != llhttp->data);
   auto &httpResponseParserContext{*std::bit_cast<http_response_parser_context *>(llhttp->data),};
   assert(false == httpResponseParserContext.tmpString.empty());
   assert(false == (bool{httpResponseParserContext.errorCode,}));
   httpResponseParserContext.errorCode = httpResponseParserContext.parser.handle_status(
      llhttp_get_status_code(llhttp),
      httpResponseParserContext.tmpString
   );
   httpResponseParserContext.tmpString = std::string_view{"",};
   return httpResponseParserContext.errorCode ? llhttp_errno::HPE_PAUSED : llhttp_errno::HPE_OK;
}

}
