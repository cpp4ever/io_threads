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
#include "common/utility.hpp" ///< for io_threads::unreachable
#include "openssl/error.hpp" ///< for io_threads::log_openssl_errors

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
   std::string_view securityToken{"",};
   tls_client_session *next{nullptr,};
   std::array<BUF_MEM, 2> bufMems
   {
      BUF_MEM{.length = 0, .data = nullptr, .max = 0, .flags = 0,},
      BUF_MEM{.length = 0, .data = nullptr, .max = 0, .flags = 0,},
   };
};

[[nodiscard]] inline int reset_bio(BIO *bio, BUF_MEM &bufMem)
{
   assert(nullptr != bio);
   assert(nullptr != bufMem.data);
   assert(0 < bufMem.max);
   assert(bufMem.length <= bufMem.max);
   assert(0 == bufMem.flags);
   bufMem.length = 0;
   bufMem.data = nullptr;
   bufMem.max = 0;
   return BIO_set_mem_buf(bio, std::addressof(bufMem), BIO_NOCLOSE);
}

inline void reset_rbio(tls_client_session &tlsClientSession)
{
   assert(nullptr != tlsClientSession.rbio);
   assert(nullptr != tlsClientSession.rbioBufMem);
   if (1 != reset_bio(tlsClientSession.rbio, *tlsClientSession.rbioBufMem)) [[unlikely]]
   {
      log_openssl_errors("[tls_client] failed to reset rBIO");
      unreachable();
   }
}

inline void reset_wbio(tls_client_session &tlsClientSession)
{
   assert(nullptr != tlsClientSession.wbio);
   assert(nullptr != tlsClientSession.wbioBufMem);
   if (1 != reset_bio(tlsClientSession.wbio, *tlsClientSession.wbioBufMem)) [[unlikely]]
   {
      log_openssl_errors("[tls_client] failed to reset wBIO");
      unreachable();
   }
}

inline void set_rbio(tls_client_session &tlsClientSession, data_chunk const &dataChunk)
{
   assert(nullptr != tlsClientSession.rbio);
   assert(nullptr != tlsClientSession.rbioBufMem);
   assert(0 == tlsClientSession.rbioBufMem->length);
   assert(nullptr == tlsClientSession.rbioBufMem->data);
   assert(0 == tlsClientSession.rbioBufMem->max);
   assert(0 == tlsClientSession.rbioBufMem->flags);
   tlsClientSession.rbioBufMem->length = dataChunk.bytesLength;
   tlsClientSession.rbioBufMem->data = std::bit_cast<char *>(dataChunk.bytes);
   tlsClientSession.rbioBufMem->max = dataChunk.bytesLength;
   if (1 != BIO_set_mem_buf(tlsClientSession.rbio, tlsClientSession.rbioBufMem, BIO_NOCLOSE)) [[unlikely]]
   {
      log_openssl_errors("[tls_client] failed to set rBIO memory chunk");
      unreachable();
   }
}

inline void set_wbio(tls_client_session &tlsClientSession, data_chunk const &dataChunk)
{
   assert(nullptr != tlsClientSession.wbio);
   assert(nullptr != tlsClientSession.wbioBufMem);
   assert(0 == tlsClientSession.wbioBufMem->length);
   assert(nullptr == tlsClientSession.wbioBufMem->data);
   assert(0 == tlsClientSession.wbioBufMem->max);
   assert(0 == tlsClientSession.wbioBufMem->flags);
   tlsClientSession.wbioBufMem->length = 0;
   tlsClientSession.wbioBufMem->data = std::bit_cast<char *>(dataChunk.bytes);
   tlsClientSession.wbioBufMem->max = dataChunk.bytesLength;
   if (1 != BIO_set_mem_buf(tlsClientSession.wbio, tlsClientSession.wbioBufMem, BIO_NOCLOSE)) [[unlikely]]
   {
      log_openssl_errors("[tls_client] failed to set wBIO memory chunk");
      unreachable();
   }
}

}
