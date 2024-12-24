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

#include "common/tls_client_status.hpp" ///< for io_threads::tls_client_status

#include <openssl/ssl.h>

#include <array> ///< for std::array
#include <cstddef> ///< for std::byte
#include <string_view> ///< for std::string_view

template<>
struct std::default_delete<SSL>
{
   constexpr default_delete() noexcept = default;
   constexpr default_delete(default_delete &&) noexcept = default;
   constexpr default_delete(default_delete const &) noexcept = default;

   constexpr default_delete &operator = (default_delete &&) noexcept = default;
   constexpr default_delete &operator = (default_delete const &) noexcept = default;

   void operator () (SSL *ssl) const
   {
      SSL_free(ssl);
   }
};

namespace io_threads
{

struct tls_client_session final
{
   std::unique_ptr<SSL> ssl;
   BIO *rbio;
   BUF_MEM *rbioBufMem{nullptr,};
   BIO *wbio;
   BUF_MEM *wbioBufMem{nullptr,};
   tls_client_status status{tls_client_status::none};
   std::byte *securityBuffer{nullptr};
   std::string_view securityToken{};
   tls_client_session *next{nullptr,};
   std::array<BUF_MEM, 2> bufMems
   {
      BUF_MEM{.length = 0, .data = nullptr, .max = 0, .flags = 0,},
      BUF_MEM{.length = 0, .data = nullptr, .max = 0, .flags = 0,},
   };
};

}
