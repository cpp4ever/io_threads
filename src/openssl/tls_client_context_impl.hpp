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
#include "io_threads/ssl_certificate.hpp" ///< for io_threads::ssl_certificate
#include "io_threads/tls_client_context.hpp" ///< for io_threads::tls_client_context
#include "openssl/error.hpp" ///< for io_threads::log_openssl_errors
#include "openssl/tls_client_session.hpp" ///< for io_threads::tls_client_session

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <algorithm> ///< for std::max
#include <array> ///< for std::array, std::to_array
#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <cstddef> ///< for size_t, std::byte
#include <memory> ///< for std::addressof, std::make_unique, std::unique_ptr
#include <new> ///< for std::align_val_t
#include <source_location> ///< for std::source_location
#include <string> ///< for std::string, std::wstring
#include <string_view> ///< for std::string_view, std::wstring_view
#include <system_error> ///< for std::error_code, std::system_category
#include <utility> ///< for std::pair

namespace io_threads
{

class tls_client_context::tls_client_context_impl final
{
public:
   tls_client_context_impl() = delete;
   tls_client_context_impl(tls_client_context_impl &&) = delete;
   tls_client_context_impl(tls_client_context_impl const &) = delete;

   [[nodiscard]] tls_client_context_impl(std::string_view const domainName, size_t const capacityOfTlsClientSessionList) :
      m_domainName{domainName,},
      m_tlsClientSessionsMemoryPool
      {
         capacityOfTlsClientSessionList,
         std::align_val_t{alignof(tls_client_session),},
         sizeof(tls_client_session),
      }
   {
      SSL_CTX_enable_ct(std::addressof(m_sslContext), SSL_CT_VALIDATION_STRICT);
      X509_VERIFY_PARAM *x509VerifyParam{X509_VERIFY_PARAM_new(),};
      X509_VERIFY_PARAM_set1_host(x509VerifyParam, domainName.data(), domainName.size());
      X509_VERIFY_PARAM_set_auth_level(x509VerifyParam, 4); ///< TLS 1.2 or above
      X509_VERIFY_PARAM_set_flags(x509VerifyParam, X509_V_FLAG_CRL_CHECK);
      X509_VERIFY_PARAM_set_hostflags(x509VerifyParam, X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT);
      X509_VERIFY_PARAM_set_purpose(x509VerifyParam, X509_PURPOSE_SSL_CLIENT);
      SSL_CTX_set1_param(std::addressof(m_sslContext), x509VerifyParam);
      X509_VERIFY_PARAM_free(x509VerifyParam);
      SSL_CTX_set_min_proto_version(std::addressof(m_sslContext), TLS1_2_VERSION);
      SSL_CTX_set_security_level(std::addressof(m_sslContext), 4); ///< TLS 1.2 or above
      for (size_t tlsClientSessionIndex{0,}; capacityOfTlsClientSessionList > tlsClientSessionIndex; ++tlsClientSessionIndex)
      {
         auto *ssl{SSL_new(std::addressof(m_sslContext)),};
         if (nullptr == ssl) [[unlikely]]
         {
            log_openssl_errors("[tls_client] failed to create SSL structure:");
            unreachable();
         }
         auto &rbio{create_memory_bio(),};
         auto &wbio{create_memory_bio(),};
         SSL_set_bio(ssl, std::addressof(rbio), std::addressof(wbio));
         assert(std::addressof(rbio) == SSL_get_rbio(ssl));
         assert(std::addressof(wbio) == SSL_get_wbio(ssl));
         auto &tlsClientSession
         {
            m_tlsClientSessionsMemoryPool.pop_object<tls_client_session>(
               tls_client_session
               {
                  .ssl = *ssl,
                  .rbio = rbio,
                  .wbio = wbio,
                  .next = std::launder(m_tlsClientSessions),
               }
            ),
         };
         m_tlsClientSessions = std::addressof(tlsClientSession);
      }
   }

   [[nodiscard]] tls_client_context_impl(
      std::string_view const domainName,
      ssl_certificate const &sslCertificate,
      size_t const capacityOfTlsClientSessionList
   ) :
      m_domainName{domainName,},
      m_tlsClientSessionsMemoryPool
      {
         capacityOfTlsClientSessionList,
         std::align_val_t{alignof(tls_client_session),},
         sizeof(tls_client_session),
      }
   {
      (void)sslCertificate;
      (void)capacityOfTlsClientSessionList;
   }

   ~tls_client_context_impl()
   {
      while (nullptr != m_tlsClientSessions)
      {
         auto *tlsClientSession = std::launder(m_tlsClientSessions);
         m_tlsClientSessions = tlsClientSession->next;
         SSL_free(std::addressof(tlsClientSession->ssl));
         m_tlsClientSessionsMemoryPool.push_object(*tlsClientSession);
      }
      SSL_CTX_free(std::addressof(m_sslContext));
   }

   tls_client_context_impl &operator = (tls_client_context_impl &&) = delete;
   tls_client_context_impl &operator = (tls_client_context_impl const &) = delete;

   [[nodiscard]] tls_client_session &acquire_session()
   {
      if (nullptr == m_tlsClientSessions) [[unlikely]]
      {
         unreachable();
      }
      auto *tlsClientSession = std::launder(m_tlsClientSessions);
      m_tlsClientSessions = tlsClientSession->next;
      return *tlsClientSession;
   }

   [[nodiscard]] std::error_code check_session_status(
      tls_client_session &tlsClientSession,
      data_chunk const dataChunk,
      size_t &bytesWritten
   )
   {
      (void)tlsClientSession;
      (void)dataChunk;
      (void)bytesWritten;
      return {};
   }

   [[nodiscard]] std::error_code decrypt_message(
      tls_client_session &session,
      data_chunk const inboundDataChunk,
      data_chunk &decryptedDataChunk,
      size_t &bytesProcessed
   )
   {
      (void)session;
      (void)inboundDataChunk;
      (void)decryptedDataChunk;
      (void)bytesProcessed;
      return {};
   }

   [[nodiscard]] std::string_view domain_name() const noexcept
   {
      return m_domainName;
   }

   [[nodiscard]] std::error_code encrypt_message(
      tls_client_session &session,
      data_chunk const dataChunk,
      size_t &bytesWritten
   )
   {
      (void)session;
      (void)dataChunk;
      (void)bytesWritten;
      return {};
   }

   void release_session(tls_client_session &tlsClientSession)
   {
      if (0 == SSL_clear(std::addressof(tlsClientSession.ssl))) [[unlikely]]
      {
         log_openssl_errors("[tls_client] failed to clear SSL structure:");
         unreachable();
      }
      tlsClientSession.next = std::launder(m_tlsClientSessions);
      m_tlsClientSessions = std::launder(std::addressof(tlsClientSession));
   }

   [[nodiscard]] std::error_code shutdown(tls_client_session &session, data_chunk const dataChunk, size_t &bytesWritten)
   {
      (void)session;
      (void)dataChunk;
      (void)bytesWritten;
      return {};
   }

   [[nodiscard]] static size_t data_capacity(tls_client_session const &session, size_t const bytesCapacity)
   {
      (void)session;
      (void)bytesCapacity;
      return 0;
   }

   [[nodiscard]] static size_t header_size(tls_client_session const &session, size_t) noexcept
   {
      (void)session;
      return 0;
   }

private:
   SSL_CTX &m_sslContext{create_ssl_context(),};
   tls_client_session *m_tlsClientSessions{nullptr,};
   std::string const m_domainName;
   memory_pool m_tlsClientSessionsMemoryPool;

   [[nodiscard]] static BIO &create_memory_bio()
   {
      auto *memoryBio{BIO_new(BIO_s_mem()),};
      if (nullptr == memoryBio) [[unlikely]]
      {
         log_openssl_errors("[tls_client] failed to create memory BIO:");
         unreachable();
      }
      return *memoryBio;
   }

   [[nodiscard]] static SSL_CTX &create_ssl_context()
   {
      auto *sslContext{SSL_CTX_new(TLS_client_method()),};
      if (nullptr == sslContext) [[unlikely]]
      {
         log_openssl_errors("[tls_client] failed to create SSL context:");
         unreachable();
      }
      return *sslContext;
   }
};

}
