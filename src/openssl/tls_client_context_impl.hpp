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

#include "common/logger.hpp" ///< for io_threads::log_error, io_threads::log_system_error
#include "common/memory_pool.hpp" ///< for io_threads::memory_pool
#include "common/tls_client_status.hpp" ///< for io_threads::tls_client_status
#include "common/utility.hpp" ///< for io_threads::unreachable
#include "io_threads/data_chunk.hpp" ///< for io_threads::data_chunk
#include "io_threads/tls_client_context.hpp" ///< for io_threads::tls_client_context
#include "openssl/error.hpp" ///< for io_threads::log_openssl_errors
#include "openssl/tls_client_session.hpp" ///< for io_threads::tls_client_session
#include "openssl/x509_store_impl.hpp" ///< for io_threads::x509_store_impl

#include <openssl/err.h>
#include <openssl/ocsp.h>
#include <openssl/ssl.h>

#include <algorithm> ///< for std::max
#include <array> ///< for std::array, std::to_array
#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <cstddef> ///< for size_t, std::byte
#include <cstring> ///< for std::memcpy
#include <memory> ///< for std::addressof, std::make_unique, std::unique_ptr
#include <new> ///< for std::align_val_t
#include <source_location> ///< for std::source_location
#include <string> ///< for std::string, std::wstring
#include <string_view> ///< for std::string_view, std::wstring_view
#include <system_error> ///< for std::error_code, std::system_category
#include <utility> ///< for std::pair

template<>
struct std::default_delete<OCSP_BASICRESP>
{
   constexpr default_delete() noexcept = default;
   constexpr default_delete(default_delete &&) noexcept = default;
   constexpr default_delete(default_delete const &) noexcept = default;

   constexpr default_delete &operator = (default_delete &&) noexcept = default;
   constexpr default_delete &operator = (default_delete const &) noexcept = default;

   void operator () (OCSP_BASICRESP *oscpDecodedResponse) const
   {
      OCSP_BASICRESP_free(oscpDecodedResponse);
   }
};

template<>
struct std::default_delete<OCSP_CERTID>
{
   constexpr default_delete() noexcept = default;
   constexpr default_delete(default_delete &&) noexcept = default;
   constexpr default_delete(default_delete const &) noexcept = default;

   constexpr default_delete &operator = (default_delete &&) noexcept = default;
   constexpr default_delete &operator = (default_delete const &) noexcept = default;

   void operator () (OCSP_CERTID *oscpDecodedResponse) const
   {
      OCSP_CERTID_free(oscpDecodedResponse);
   }
};

template<>
struct std::default_delete<OCSP_RESPONSE>
{
   constexpr default_delete() noexcept = default;
   constexpr default_delete(default_delete &&) noexcept = default;
   constexpr default_delete(default_delete const &) noexcept = default;

   constexpr default_delete &operator = (default_delete &&) noexcept = default;
   constexpr default_delete &operator = (default_delete const &) noexcept = default;

   void operator () (OCSP_RESPONSE *oscpResponse) const
   {
      OCSP_RESPONSE_free(oscpResponse);
   }
};

template<>
struct std::default_delete<X509>
{
   constexpr default_delete() noexcept = default;
   constexpr default_delete(default_delete &&) noexcept = default;
   constexpr default_delete(default_delete const &) noexcept = default;

   constexpr default_delete &operator = (default_delete &&) noexcept = default;
   constexpr default_delete &operator = (default_delete const &) noexcept = default;

   void operator () (X509 *x509) const
   {
      X509_free(x509);
   }
};

namespace io_threads
{

class tls_client_context::tls_client_context_impl final
{
public:
   tls_client_context_impl() = delete;
   tls_client_context_impl(tls_client_context_impl &&) = delete;
   tls_client_context_impl(tls_client_context_impl const &) = delete;

   [[nodiscard]] tls_client_context_impl(
      std::shared_ptr<x509_store_impl> const &x509Store,
      std::string_view const &domainName,
      size_t const tlsSessionListCapacity
   ) :
      m_sslContext{x509Store->create_ssl_context(),},
      m_securityBuffersMemoryPool
      {
         tlsSessionListCapacity,
         std::align_val_t{alignof(std::byte),},
         tls_packet_size_limit,
      },
      m_domainName{domainName,},
      m_tlsClientSessionsMemoryPool
      {
         tlsSessionListCapacity,
         std::align_val_t{alignof(tls_client_session),},
         sizeof(tls_client_session),
      }
   {
      assert(0 < tlsSessionListCapacity);
      assert(nullptr != SSL_CTX_get0_param(m_sslContext.get()));
      if (1 == X509_VERIFY_PARAM_set1_host(SSL_CTX_get0_param(m_sslContext.get()), domainName.data(), domainName.size())) [[likely]]
      {
         [[maybe_unused]] auto const hostname{X509_VERIFY_PARAM_get0_host(SSL_CTX_get0_param(m_sslContext.get()), 0),};
         assert(nullptr != hostname);
         assert(hostname == domainName);
      }
      else
      {
         log_openssl_errors("[tls_client] failed to set DNS hostname");
         unreachable();
      }
      [[maybe_unused]] auto const sslContextMode{SSL_CTX_set_mode(m_sslContext.get(), SSL_MODE_AUTO_RETRY | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER),};
      assert((SSL_MODE_AUTO_RETRY | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER) == sslContextMode);
      if (1 == SSL_CTX_set_tlsext_status_cb(m_sslContext.get(), ocsp_callback)) [[likely]]
      {
         [[maybe_unused]] int (*ocspCallback)(SSL *, void *){nullptr,};
         assert(1 == SSL_CTX_get_tlsext_status_cb(m_sslContext.get(), std::addressof(ocspCallback)));
         assert(&ocsp_callback == ocspCallback);
      }
      else
      {
         log_openssl_errors("[tls_client] failed to store OCSP callback");
         unreachable();
      }
      if (1 == SSL_CTX_set_tlsext_status_arg(m_sslContext.get(), this)) [[likely]]
      {
         [[maybe_unused]] void *ocspCallbackArg{nullptr,};
         assert(1 == SSL_CTX_get_tlsext_status_arg(m_sslContext.get(), std::addressof(ocspCallbackArg)));
         assert(this == ocspCallbackArg);
      }
      else
      {
         log_openssl_errors("[tls_client] failed to store userdata for OCSP callback");
         unreachable();
      }
      m_utilityBuffer.resize(tls_packet_size_limit, std::byte{0,});
      for (size_t tlsClientSessionIndex{0,}; tlsSessionListCapacity > tlsClientSessionIndex; ++tlsClientSessionIndex)
      {
         std::unique_ptr<SSL> ssl{SSL_new(m_sslContext.get()),};
         if (nullptr == ssl) [[unlikely]]
         {
            log_openssl_errors("[tls_client] failed to create SSL structure");
            unreachable();
         }
         auto *rbio{create_memory_bio(),};
         auto *wbio{create_memory_bio(),};
         auto &tlsClientSession
         {
            m_tlsClientSessionsMemoryPool.pop_object<tls_client_session>(
               tls_client_session
               {
                  .ssl = std::move(ssl),
                  .rbio = rbio,
                  .wbio = wbio,
                  .next = std::launder(m_tlsClientSessions),
               }
            ),
         };
         tlsClientSession.rbioBufMem = std::addressof(tlsClientSession.bufMems[0]);
         tlsClientSession.wbioBufMem = std::addressof(tlsClientSession.bufMems[1]);
         auto bioArray = std::to_array(
            {
               std::make_pair(tlsClientSession.rbio, tlsClientSession.rbioBufMem),
               std::make_pair(tlsClientSession.wbio, tlsClientSession.wbioBufMem),
            }
         );
         for (auto &[bio, bioBufMem] : bioArray)
         {
            if (1 != BIO_set_mem_buf(bio, bioBufMem, BIO_NOCLOSE)) [[unlikely]]
            {
               log_openssl_errors("[tls_client] failed to setup empty memory BIO");
               unreachable();
            }
         }
         SSL_set_bio(tlsClientSession.ssl.get(), tlsClientSession.rbio, tlsClientSession.wbio);
         assert(tlsClientSession.rbio == SSL_get_rbio(tlsClientSession.ssl.get()));
         assert(tlsClientSession.wbio == SSL_get_wbio(tlsClientSession.ssl.get()));
         m_tlsClientSessions = std::addressof(tlsClientSession);
      }
      assert(nullptr != m_tlsClientSessions);
   }

   ~tls_client_context_impl()
   {
      while (nullptr != m_tlsClientSessions)
      {
         auto *tlsClientSession = std::launder(m_tlsClientSessions);
         m_tlsClientSessions = tlsClientSession->next;
         m_tlsClientSessionsMemoryPool.push_object(*tlsClientSession);
      }
   }

   tls_client_context_impl &operator = (tls_client_context_impl &&) = delete;
   tls_client_context_impl &operator = (tls_client_context_impl const &) = delete;

   [[nodiscard]] tls_client_session &acquire_session()
   {
      if (nullptr == m_tlsClientSessions) [[unlikely]]
      {
         log_error(std::source_location::current(), "[tls_client] too few TLS sessions provided, please increase capacity of TLS session list");
         unreachable();
      }
      ERR_clear_error();
      auto &tlsClientSession = *std::launder(m_tlsClientSessions);
      m_tlsClientSessions = std::launder(tlsClientSession.next);
      tlsClientSession.next = nullptr;
      SSL_set_tlsext_host_name(tlsClientSession.ssl.get(), m_domainName.data());
      assert(TLSEXT_STATUSTYPE_ocsp == SSL_get_tlsext_status_type(tlsClientSession.ssl.get()));
      tlsClientSession.status = tls_client_status::handshake;
      tlsClientSession.securityBuffer = m_securityBuffersMemoryPool.pop_memory_chunk();
      set_wbio(
         tlsClientSession,
         data_chunk{.bytes = tlsClientSession.securityBuffer, .bytesLength = m_securityBuffersMemoryPool.memory_chunk_size(),}
      );
      if (auto const returnCode{SSL_connect(tlsClientSession.ssl.get()),}; 0 >= returnCode) [[unlikely]]
      {
         auto const errorCode{make_ssl_error_code(*tlsClientSession.ssl, returnCode),};
         if (errorCode != make_ssl_error_code(SSL_ERROR_WANT_READ)) [[unlikely]]
         {
            log_openssl_errors("[tls_client] failed to start TLS handshake");
            unreachable();
         }
      }
      auto const bytesWritten{BIO_ctrl_pending(tlsClientSession.wbio),};
      assert(m_securityBuffersMemoryPool.memory_chunk_size() >= bytesWritten);
      tlsClientSession.securityToken = std::string_view{std::bit_cast<char const *>(tlsClientSession.securityBuffer), bytesWritten,};
      reset_wbio(tlsClientSession);
      return tlsClientSession;
   }

   [[nodiscard]] std::error_code check_session_status(tls_client_session &tlsClientSession, data_chunk const &dataChunk, size_t &bytesWritten)
   {
      bytesWritten = 0;
      if (nullptr != tlsClientSession.securityBuffer) [[unlikely]] ///< handshake or shutdown
      {
         if (true == tlsClientSession.securityToken.empty())
         {
            if (tls_client_status::handshake_complete == tlsClientSession.status) [[unlikely]]
            {
               tlsClientSession.status = tls_client_status::ready;
            }
            m_securityBuffersMemoryPool.push_memory_chunk(tlsClientSession.securityBuffer);
            tlsClientSession.securityBuffer = nullptr;
            return std::error_code{};
         }
         assert(tlsClientSession.securityToken.size() <= dataChunk.bytesLength);
         std::memcpy(dataChunk.bytes, tlsClientSession.securityToken.data(), tlsClientSession.securityToken.size());
         bytesWritten = tlsClientSession.securityToken.size();
         tlsClientSession.securityToken = std::string_view{"",};
         return std::error_code{};
      }
      assert(true == tlsClientSession.securityToken.empty());
      return std::error_code{};
   }

   [[nodiscard]] std::error_code decrypt_message(
      tls_client_session &tlsClientSession,
      data_chunk const &inboundDataChunk,
      data_chunk &decryptedDataChunk,
      size_t &bytesProcessed
   )
   {
      assert(nullptr != tlsClientSession.ssl);
      assert(nullptr != tlsClientSession.rbio);
      assert(nullptr != tlsClientSession.rbioBufMem);
      assert(0 == tlsClientSession.rbioBufMem->length);
      assert(nullptr == tlsClientSession.rbioBufMem->data);
      assert(0 == tlsClientSession.rbioBufMem->max);
      assert(0 == tlsClientSession.rbioBufMem->flags);
      assert(nullptr != tlsClientSession.wbio);
      assert(nullptr != tlsClientSession.wbioBufMem);
      assert(0 == tlsClientSession.wbioBufMem->length);
      assert(nullptr == tlsClientSession.wbioBufMem->data);
      assert(0 == tlsClientSession.wbioBufMem->max);
      assert(0 == tlsClientSession.wbioBufMem->flags);
      assert(true == tlsClientSession.securityToken.empty());
      assert(nullptr == tlsClientSession.next);
      assert(nullptr != inboundDataChunk.bytes);
      assert(0 < inboundDataChunk.bytesLength);
      decryptedDataChunk = {.bytes = nullptr, .bytesLength = 0,};
      if (1 == SSL_is_init_finished(tlsClientSession.ssl.get())) [[likely]]
      {
         ERR_clear_error();
         set_rbio(tlsClientSession, inboundDataChunk);
         std::byte *securityBuffer{tlsClientSession.securityBuffer,};
         if (nullptr == securityBuffer) [[likely]]
         {
            securityBuffer = m_securityBuffersMemoryPool.pop_memory_chunk();
         }
         else if (tls_client_status::handshake_complete == tlsClientSession.status) [[unlikely]]
         {
            tlsClientSession.status = tls_client_status::ready;
         }
         set_wbio(
            tlsClientSession,
            data_chunk{.bytes = securityBuffer, .bytesLength = m_securityBuffersMemoryPool.memory_chunk_size(),}
         );
         std::error_code errorCode{};
         if (
            auto const returnCode{SSL_read_ex(tlsClientSession.ssl.get(), m_utilityBuffer.data(), m_utilityBuffer.size(), std::addressof(decryptedDataChunk.bytesLength)),};
            0 >= returnCode
         ) [[unlikely]]
         {
            errorCode = make_ssl_error_code(*tlsClientSession.ssl, returnCode);
            if (
               true
               && (make_ssl_error_code(SSL_ERROR_WANT_READ) != errorCode)
               && (make_ssl_error_code(SSL_ERROR_ZERO_RETURN) != errorCode)
            ) [[unlikely]]
            {
               log_openssl_errors("[tls_client] failed to decrypt message");
            }
         }
         auto const bytesWritten{BIO_ctrl_pending(tlsClientSession.wbio),};
         assert(m_securityBuffersMemoryPool.memory_chunk_size() >= bytesWritten);
         reset_wbio(tlsClientSession);
         assert(BIO_ctrl_pending(tlsClientSession.rbio) <= inboundDataChunk.bytesLength);
         bytesProcessed = inboundDataChunk.bytesLength - BIO_ctrl_pending(tlsClientSession.rbio);
         reset_rbio(tlsClientSession);
         if (0 == bytesWritten) [[likely]]
         {
            tlsClientSession.securityBuffer = nullptr;
            m_securityBuffersMemoryPool.push_memory_chunk(securityBuffer);
         }
         else
         {
            tlsClientSession.securityBuffer = securityBuffer;
            tlsClientSession.securityToken = std::string_view{std::bit_cast<char const *>(securityBuffer), bytesWritten,};
         }
         if (false == bool{errorCode,}) [[likely]]
         {
            decryptedDataChunk.bytes = m_utilityBuffer.data();
         }
         else
         {
            decryptedDataChunk.bytesLength = 0;
            if (make_ssl_error_code(SSL_ERROR_ZERO_RETURN) == errorCode)
            {
               if (tls_client_status::none != tlsClientSession.status)
               {
                  return std::make_error_code(std::errc::connection_reset);
               }
            }
            else if (make_ssl_error_code(SSL_ERROR_WANT_READ) != errorCode)
            {
               return errorCode;
            }
         }
      }
      else
      {
         assert(tls_client_status::handshake == tlsClientSession.status);
         ERR_clear_error();
         set_rbio(
            tlsClientSession,
            data_chunk{.bytes = inboundDataChunk.bytes, .bytesLength = inboundDataChunk.bytesLength,}
         );
         auto *securityBuffer
         {
            (nullptr != tlsClientSession.securityBuffer)
               ? tlsClientSession.securityBuffer
               : m_securityBuffersMemoryPool.pop_memory_chunk()
         };
         set_wbio(
            tlsClientSession,
            data_chunk{.bytes = securityBuffer, .bytesLength = m_securityBuffersMemoryPool.memory_chunk_size(),}
         );
         std::error_code errorCode{};
         if (
            auto const returnCode{SSL_do_handshake(tlsClientSession.ssl.get()),};
            0 >= returnCode
         )
         {
            errorCode = make_ssl_error_code(*tlsClientSession.ssl, returnCode);
            if (errorCode != make_ssl_error_code(SSL_ERROR_WANT_READ)) [[unlikely]]
            {
               log_openssl_errors("[tls_client] failed to complete TLS handshake");
            }
         }
         auto const bytesWritten{BIO_ctrl_pending(tlsClientSession.wbio),};
         assert(m_securityBuffersMemoryPool.memory_chunk_size() >= bytesWritten);
         reset_wbio(tlsClientSession);
         assert(BIO_ctrl_pending(tlsClientSession.rbio) <= inboundDataChunk.bytesLength);
         bytesProcessed = inboundDataChunk.bytesLength - BIO_ctrl_pending(tlsClientSession.rbio);
         reset_rbio(tlsClientSession);
         if (false == bool{errorCode,})
         {
            if (0 == bytesWritten)
            {
               tlsClientSession.status = tls_client_status::ready;
               tlsClientSession.securityBuffer = nullptr;
               m_securityBuffersMemoryPool.push_memory_chunk(securityBuffer);
            }
            else
            {
               tlsClientSession.status = tls_client_status::handshake_complete;
               tlsClientSession.securityBuffer = securityBuffer;
               tlsClientSession.securityToken = std::string_view{std::bit_cast<char const *>(securityBuffer), bytesWritten,};
            }
         }
         else if (errorCode == make_ssl_error_code(SSL_ERROR_WANT_READ))
         {
            tlsClientSession.securityBuffer = securityBuffer;
            tlsClientSession.securityToken = std::string_view{std::bit_cast<char const *>(securityBuffer), bytesWritten,};
            errorCode = std::error_code{};
         }
         else
         {
            bytesProcessed = inboundDataChunk.bytesLength;
            if (0 == bytesWritten)
            {
               tlsClientSession.securityBuffer = nullptr;
               m_securityBuffersMemoryPool.push_memory_chunk(securityBuffer);
            }
            else
            {
               tlsClientSession.securityBuffer = securityBuffer;
               tlsClientSession.securityToken = std::string_view{std::bit_cast<char const *>(securityBuffer), bytesWritten,};
            }
         }
         return errorCode;
      }
      return std::error_code{};
   }

   [[nodiscard]] std::string const &domain_name() const noexcept
   {
      return m_domainName;
   }

   [[nodiscard]] std::error_code encrypt_message(
      tls_client_session &tlsClientSession,
      data_chunk const &dataChunk,
      size_t &bytesWritten
   )
   {
      assert(nullptr != tlsClientSession.ssl);
      assert(nullptr != tlsClientSession.rbio);
      assert(nullptr != tlsClientSession.rbioBufMem);
      assert(0 == tlsClientSession.rbioBufMem->length);
      assert(nullptr == tlsClientSession.rbioBufMem->data);
      assert(0 == tlsClientSession.rbioBufMem->max);
      assert(0 == tlsClientSession.rbioBufMem->flags);
      assert(nullptr != tlsClientSession.wbio);
      assert(nullptr != tlsClientSession.wbioBufMem);
      assert(0 == tlsClientSession.wbioBufMem->length);
      assert(nullptr == tlsClientSession.wbioBufMem->data);
      assert(0 == tlsClientSession.wbioBufMem->max);
      assert(0 == tlsClientSession.wbioBufMem->flags);
      assert(tls_client_status::ready == tlsClientSession.status);
      assert(nullptr == tlsClientSession.securityBuffer);
      assert(true == tlsClientSession.securityToken.empty());
      assert(nullptr == tlsClientSession.next);
      assert(nullptr != dataChunk.bytes);
      assert(SSL3_RT_MAX_ENCRYPTED_OVERHEAD < dataChunk.bytesLength);
      assert(0 < bytesWritten);
      assert((SSL3_RT_MAX_ENCRYPTED_OVERHEAD + bytesWritten) <= dataChunk.bytesLength);
      ERR_clear_error();
      set_wbio(tlsClientSession, dataChunk);
      size_t bytesEncoded{0,};
      if (
         auto const returnCode{SSL_write_ex(tlsClientSession.ssl.get(), dataChunk.bytes + SSL3_RT_MAX_ENCRYPTED_OVERHEAD, bytesWritten, std::addressof(bytesEncoded)),};
         0 == returnCode
      ) [[unlikely]]
      {
         auto const errorCode{make_ssl_error_code(ERR_peek_last_error()),};
         log_openssl_errors("[tls_client] failed to encrypt message");
         reset_wbio(tlsClientSession);
         return errorCode;
      }
      assert(bytesEncoded == bytesWritten);
      bytesWritten = BIO_ctrl_pending(tlsClientSession.wbio);
      assert(bytesWritten <= dataChunk.bytesLength);
      reset_wbio(tlsClientSession);
      return std::error_code{};
   }

   void release_session(tls_client_session &tlsClientSession)
   {
      if (0 == SSL_clear(tlsClientSession.ssl.get())) [[unlikely]]
      {
         log_openssl_errors("[tls_client] failed to clear SSL structure");
         unreachable();
      }
      if (nullptr != tlsClientSession.securityBuffer)
      {
         m_securityBuffersMemoryPool.push_memory_chunk(tlsClientSession.securityBuffer);
         tlsClientSession.securityBuffer = nullptr;
      }
      tlsClientSession.securityToken = std::string_view{"",};
      tlsClientSession.next = std::launder(m_tlsClientSessions);
      m_tlsClientSessions = std::launder(std::addressof(tlsClientSession));
   }

   [[nodiscard]] std::error_code shutdown(tls_client_session &tlsClientSession, data_chunk const &dataChunk, size_t &bytesWritten)
   {
      assert(tls_client_status::none != tlsClientSession.status);
      assert(nullptr != dataChunk.bytes);
      if (false == tlsClientSession.securityToken.empty())
      {
         assert(nullptr != tlsClientSession.securityBuffer);
         std::string_view const securityToken{tlsClientSession.securityToken,};
         tlsClientSession.securityToken = std::string_view{"",};
         std::memcpy(dataChunk.bytes, securityToken.data(), securityToken.size());
         bytesWritten = securityToken.size();
         return std::error_code{};
      }
      if (tls_client_status::handshake == tlsClientSession.status)
      {
         bytesWritten = 0;
         return std::error_code{};
      }
      set_wbio(tlsClientSession, dataChunk);
      std::error_code errorCode{};
      if (auto const returnCode{SSL_shutdown(tlsClientSession.ssl.get()),}; 0 > returnCode) [[unlikely]]
      {
         errorCode = make_ssl_error_code(*tlsClientSession.ssl, returnCode);
         log_openssl_errors("[tls_client] failed to shutdown session");
         bytesWritten = 0;
      }
      else
      {
         assert(BIO_ctrl_pending(tlsClientSession.wbio) <= dataChunk.bytesLength);
         bytesWritten = BIO_ctrl_pending(tlsClientSession.wbio);
      }
      reset_wbio(tlsClientSession);
      tlsClientSession.status = tls_client_status::none;
      return errorCode;
   }

   [[nodiscard]] static data_chunk prepare_to_encrypt(tls_client_session const &, data_chunk const &dataChunk)
   {
      assert(SSL3_RT_MAX_ENCRYPTED_OVERHEAD < dataChunk.bytesLength);
      return data_chunk
      {
         .bytes = dataChunk.bytes + SSL3_RT_MAX_ENCRYPTED_OVERHEAD,
         .bytesLength = std::min<size_t>(SSL3_RT_MAX_PLAIN_LENGTH, dataChunk.bytesLength - SSL3_RT_MAX_ENCRYPTED_OVERHEAD),
      };
   }

private:
   std::unique_ptr<SSL_CTX> m_sslContext;
   std::vector<std::byte> m_utilityBuffer{};
   memory_pool m_securityBuffersMemoryPool;
   tls_client_session *m_tlsClientSessions{nullptr,};
   std::string const m_domainName;
   memory_pool m_tlsClientSessionsMemoryPool;

   [[nodiscard]] static BIO *create_memory_bio()
   {
      auto *memoryBio{BIO_new(BIO_s_mem()),};
      if (nullptr == memoryBio) [[unlikely]]
      {
         log_openssl_errors("[tls_client] failed to create memory BIO");
         unreachable();
      }
      return memoryBio;
   }

   [[nodiscard]] static int ocsp_callback(SSL *ssl, void *userdata)
   {
      assert(nullptr != ssl);
      assert(nullptr != userdata);
      auto &self{*std::bit_cast<tls_client_context_impl *>(userdata),};
      assert(self.m_sslContext.get() == SSL_get_SSL_CTX(ssl));
      uint8_t *oscpStatus{nullptr,};
      auto const oscpStatusSize{static_cast<long>(SSL_get_tlsext_status_ocsp_resp(ssl, std::addressof(oscpStatus))),};
      if (-1 == oscpStatusSize)
      {
         return 1;
      }
      uint8_t const *oscpStatusConst{oscpStatus,};
      std::unique_ptr<OCSP_RESPONSE> const oscpResponse{d2i_OCSP_RESPONSE(nullptr, std::addressof(oscpStatusConst), oscpStatusSize),};
      if (nullptr == oscpResponse) [[unlikely]]
      {
         log_openssl_errors("[tls_client] failed to get OSCP response");
         return -1;
      }
      auto const oscpResponseStatus{OCSP_response_status(oscpResponse.get()),};
      if (OCSP_RESPONSE_STATUS_SUCCESSFUL != oscpResponseStatus) [[unlikely]]
      {
         log_openssl_errors("[tls_client] failed to OSCP request failed");
         return -1;
      }
      std::unique_ptr<OCSP_BASICRESP> const oscpDecodedResponse{OCSP_response_get1_basic(oscpResponse.get()),};
      if (nullptr == oscpDecodedResponse) [[unlikely]]
      {
         log_openssl_errors("[tls_client] failed to decode OSCP response");
         return -1;
      }
      auto *clientCertificateChain{SSL_get_peer_cert_chain(ssl),};
      if (nullptr == clientCertificateChain) [[unlikely]]
      {
         log_openssl_errors("[tls_client] failed to get cerificate chain");
         return -1;
      }
      auto *x509Store{SSL_CTX_get_cert_store(self.m_sslContext.get()),};
      assert(nullptr != x509Store);
      if (OCSP_basic_verify(oscpDecodedResponse.get(), clientCertificateChain, x509Store, 0) <= 0) [[unlikely]]
      {
         log_openssl_errors("[tls_client] failed to verify OSCP response");
         return -1;
      }
      std::unique_ptr<X509> const peerCertificate{SSL_get1_peer_certificate(ssl),};
      if (nullptr == peerCertificate) [[unlikely]]
      {
         log_openssl_errors("[tls_client] failed to get peer cerificate");
         return -1;
      }
      std::unique_ptr<OCSP_CERTID> ocspCertificateId{nullptr,};
      for (int x509Index{0,}; sk_X509_num(clientCertificateChain) > x509Index; ++x509Index)
      {
         auto *clientCertificate{sk_X509_value(clientCertificateChain, x509Index),};
         if (X509_check_issued(clientCertificate, peerCertificate.get()) == X509_V_OK)
         {
            ocspCertificateId = std::unique_ptr<OCSP_CERTID>{OCSP_cert_to_id(nullptr, peerCertificate.get(), clientCertificate),};
            break;
         }
      }
      if (nullptr == ocspCertificateId) [[unlikely]]
      {
         log_openssl_errors("[tls_client] failed to get OSCP cerificate identifier");
         return -1;
      }
      int oscpCertificateStatus{V_OCSP_CERTSTATUS_GOOD,};
      int oscpCrlReason{OCSP_REVOKED_STATUS_NOSTATUS,};
      ASN1_GENERALIZEDTIME *revokationTime{nullptr,};
      ASN1_GENERALIZEDTIME *lastUpdateTime{nullptr,};
      ASN1_GENERALIZEDTIME *nextUpdateTime{nullptr,};
      if (
         0 == OCSP_resp_find_status(
            oscpDecodedResponse.get(),
            ocspCertificateId.get(),
            std::addressof(oscpCertificateStatus),
            std::addressof(oscpCrlReason),
            std::addressof(revokationTime),
            std::addressof(lastUpdateTime),
            std::addressof(nextUpdateTime)
         )
      ) [[unlikely]]
      {
         log_openssl_errors("[tls_client] failed to handle OSCP response");
         return -1;
      }
      if (0 == OCSP_check_validity(lastUpdateTime, nextUpdateTime, 300L, -1L)) [[unlikely]]
      {
         log_openssl_errors("[tls_client] OSCP response has expired");
         return -1;
      }
      return (V_OCSP_CERTSTATUS_GOOD == oscpCertificateStatus) ? 1 : 0;
   }
};

bool tls1_3_available()
{
   constexpr auto openssl_v1_1_1_prerepease = 0x1010001FL;
   constexpr auto openssl_v1_1_1_repease = 0x10100010L;
   auto const opensslVersion{OpenSSL_version_num(),};
   return (openssl_v1_1_1_prerepease < opensslVersion) || (openssl_v1_1_1_repease == opensslVersion);
}

}
