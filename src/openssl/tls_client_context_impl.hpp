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
      size_t const capacityOfTlsClientSessionList
   ) :
      m_sslContext{x509Store->create_ssl_context(),},
      m_securityBuffersMemoryPool
      {
         capacityOfTlsClientSessionList,
         std::align_val_t{alignof(std::byte),},
         tls_packet_size_limit,
      },
      m_domainName{domainName,},
      m_tlsClientSessionsMemoryPool
      {
         capacityOfTlsClientSessionList,
         std::align_val_t{alignof(tls_client_session),},
         sizeof(tls_client_session),
      }
   {
      assert(0 < capacityOfTlsClientSessionList);
      X509_VERIFY_PARAM_set1_host(SSL_CTX_get0_param(m_sslContext.get()), domainName.data(), domainName.size());
      for (size_t tlsClientSessionIndex{0,}; capacityOfTlsClientSessionList > tlsClientSessionIndex; ++tlsClientSessionIndex)
      {
         std::unique_ptr<SSL> ssl{SSL_new(m_sslContext.get()),};
         if (nullptr == ssl) [[unlikely]]
         {
            log_openssl_errors("[tls_client] failed to create SSL structure:");
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
               log_openssl_errors("[tls_client] failed to setup empty memory BIO:");
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
      auto &tlsClientSession = *std::launder(m_tlsClientSessions);
      m_tlsClientSessions = tlsClientSession.next;
      SSL_set_tlsext_host_name(tlsClientSession.ssl.get(), m_domainName.data());
      assert(TLSEXT_STATUSTYPE_ocsp == SSL_get_tlsext_status_type(tlsClientSession.ssl.get()));
      tlsClientSession.status = tls_client_status::handshake;
      tlsClientSession.securityBuffer = m_securityBuffersMemoryPool.pop();
      assert(0 == tlsClientSession.wbioBufMem->length);
      tlsClientSession.wbioBufMem->data = std::bit_cast<char *>(tlsClientSession.securityBuffer);
      tlsClientSession.wbioBufMem->max = m_securityBuffersMemoryPool.memory_size();
      BIO_set_mem_buf(tlsClientSession.wbio, tlsClientSession.wbioBufMem, BIO_NOCLOSE);
      auto const returnCode{SSL_connect(tlsClientSession.ssl.get()),};
      if (auto const errorCode = SSL_get_error(tlsClientSession.ssl.get(), returnCode); SSL_ERROR_WANT_READ != errorCode) [[unlikely]]
      {
         log_openssl_errors("[tls_client] failed to start TLS handshake:");
         unreachable();
      }
      tlsClientSession.securityToken = std::string_view
      {
         std::bit_cast<char const *>(tlsClientSession.securityBuffer),
         tlsClientSession.wbioBufMem->length,
      };
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
            m_securityBuffersMemoryPool.push(tlsClientSession.securityBuffer);
            tlsClientSession.securityBuffer = nullptr;
            return {};
         }
         if (tlsClientSession.securityToken.size() > dataChunk.bytesLength) [[unlikely]]
         {
            log_error(
               std::source_location::current(),
               "[tls_client] {} byte send buffer is too small for {} byte security token",
               dataChunk.bytesLength,
               tlsClientSession.securityToken.size()
            );
            unreachable();
         }
         std::memcpy(dataChunk.bytes, tlsClientSession.securityToken.data(), tlsClientSession.securityToken.size());
         bytesWritten = tlsClientSession.securityToken.size();
         tlsClientSession.wbioBufMem->length = 0;
         tlsClientSession.wbioBufMem->data = nullptr;
         tlsClientSession.wbioBufMem->max = 0;
         BIO_set_mem_buf(tlsClientSession.wbio, tlsClientSession.wbioBufMem, BIO_NOCLOSE);
         tlsClientSession.securityToken = std::string_view{"",};
         return {};
      }
      assert(true == tlsClientSession.securityToken.empty());
      return {};
   }

   [[nodiscard]] std::error_code verify_oscp_response(tls_client_session &tlsClientSession)
   {
      uint8_t *oscpStatus{nullptr,};
      auto const oscpStatusSize{static_cast<long>(SSL_get_tlsext_status_ocsp_resp(tlsClientSession.ssl.get(), std::addressof(oscpStatus))),};
      if (nullptr == oscpStatus) [[unlikely]]
      {
         log_openssl_errors("[tls_client] failed to get OSCP status:");
         unreachable();
      }
      uint8_t const *oscpStatusConst{oscpStatus,};
      std::unique_ptr<OCSP_RESPONSE> const oscpResponse
      {
         d2i_OCSP_RESPONSE(nullptr, std::addressof(oscpStatusConst), oscpStatusSize),
      };
      if (nullptr == oscpResponse) [[unlikely]]
      {
         log_openssl_errors("[tls_client] failed to get OSCP response:");
         unreachable();
      }
      auto const oscpResponseStatus{OCSP_response_status(oscpResponse.get()),};
      if (OCSP_RESPONSE_STATUS_SUCCESSFUL != oscpResponseStatus) [[unlikely]]
      {
         log_openssl_errors("[tls_client] failed to OSCP request failed:");
         unreachable();
      }
      std::unique_ptr<OCSP_BASICRESP> const oscpDecodedResponse{OCSP_response_get1_basic(oscpResponse.get()),};
      if (nullptr == oscpDecodedResponse) [[unlikely]]
      {
         log_openssl_errors("[tls_client] failed to decode OSCP response:");
         unreachable();
      }
      auto *clientCertificateChain{SSL_get_peer_cert_chain(tlsClientSession.ssl.get()),};
      if (nullptr == clientCertificateChain) [[unlikely]]
      {
         log_openssl_errors("[tls_client] failed to get cerificate chain:");
         unreachable();
      }
      auto *x509Store{SSL_CTX_get_cert_store(m_sslContext.get()),};
      assert(nullptr != x509Store);
      if (OCSP_basic_verify(oscpDecodedResponse.get(), clientCertificateChain, x509Store, 0) <= 0) [[unlikely]]
      {
         log_openssl_errors("[tls_client] failed to verify OSCP response:");
         unreachable();
      }
      std::unique_ptr<X509> const peerCertificate{SSL_get1_peer_certificate(tlsClientSession.ssl.get()),};
      if (nullptr == peerCertificate) [[unlikely]]
      {
         log_openssl_errors("[tls_client] failed to get peer cerificate:");
         unreachable();
      }
      std::unique_ptr<OCSP_CERTID> ocspCertificateId{nullptr,};
      for (int x509Index{0,}; sk_X509_num(clientCertificateChain) > x509Index; ++x509Index)
      {
         auto *clientCertificate{sk_X509_value(clientCertificateChain, x509Index),};
         if (X509_check_issued(clientCertificate, peerCertificate.get()) == X509_V_OK)
         {
            ocspCertificateId = std::unique_ptr<OCSP_CERTID>{OCSP_cert_to_id(EVP_sha1(), peerCertificate.get(), clientCertificate),};
            break;
         }
      }
      if (nullptr == ocspCertificateId) [[unlikely]]
      {
         log_openssl_errors("[tls_client] failed to get OSCP cerificate identifier:");
         unreachable();
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
         log_openssl_errors("[tls_client] failed to handle OSCP response:");
         unreachable();
      }
      if (0 == OCSP_check_validity(lastUpdateTime, nextUpdateTime, 300L, -1L)) [[unlikely]]
      {
         log_openssl_errors("[tls_client] OSCP response has expired:");
         unreachable();
      }
      switch (oscpCertificateStatus)
      {
      case V_OCSP_CERTSTATUS_GOOD: return std::error_code{};
      case V_OCSP_CERTSTATUS_REVOKED: return make_x509_error_code(X509_V_ERR_CERT_REVOKED);

      [[unlikely]] default:
      {
         unreachable();
      }
      }
   }

   [[nodiscard]] std::error_code decrypt_message(
      tls_client_session &tlsClientSession,
      data_chunk const &inboundDataChunk,
      data_chunk &decryptedDataChunk,
      size_t &bytesProcessed
   )
   {
      assert(true == tlsClientSession.securityToken.empty());
      decryptedDataChunk = {};
      if (tls_client_status::handshake == tlsClientSession.status)
      {
         tlsClientSession.rbioBufMem->length = inboundDataChunk.bytesLength;
         tlsClientSession.rbioBufMem->data = std::bit_cast<char *>(inboundDataChunk.bytes);
         tlsClientSession.rbioBufMem->max = inboundDataChunk.bytesLength;
         BIO_set_mem_buf(tlsClientSession.rbio, tlsClientSession.rbioBufMem, BIO_NOCLOSE);
         auto *securityBuffer
         {
            (nullptr != tlsClientSession.securityBuffer)
               ? tlsClientSession.securityBuffer
               : m_securityBuffersMemoryPool.pop()
         };
         assert(0 == tlsClientSession.wbioBufMem->length);
         tlsClientSession.wbioBufMem->data = std::bit_cast<char *>(securityBuffer);
         tlsClientSession.wbioBufMem->max = m_securityBuffersMemoryPool.memory_size();
         BIO_set_mem_buf(tlsClientSession.wbio, tlsClientSession.wbioBufMem, BIO_NOCLOSE);
         auto const returnCode{SSL_connect(tlsClientSession.ssl.get()),};
         bytesProcessed = tlsClientSession.rbioBufMem->length;
         tlsClientSession.rbioBufMem->length = 0;
         tlsClientSession.rbioBufMem->data = nullptr;
         tlsClientSession.rbioBufMem->max = 0;
         BIO_set_mem_buf(tlsClientSession.rbio, tlsClientSession.rbioBufMem, BIO_NOCLOSE);
         auto errorCode{make_ssl_error_code(*tlsClientSession.ssl, returnCode)};
         if (false == bool{errorCode,})
         {
            errorCode = verify_oscp_response(tlsClientSession);
         }
         if (false == bool{errorCode,})
         {
            if (0 == tlsClientSession.wbioBufMem->length)
            {
               tlsClientSession.status = tls_client_status::ready;
               tlsClientSession.wbioBufMem->data = nullptr;
               tlsClientSession.wbioBufMem->max = 0;
               BIO_set_mem_buf(tlsClientSession.wbio, tlsClientSession.wbioBufMem, BIO_NOCLOSE);
               tlsClientSession.securityBuffer = nullptr;
               m_securityBuffersMemoryPool.push(securityBuffer);
            }
            else
            {
               tlsClientSession.status = tls_client_status::handshake_complete;
               tlsClientSession.securityBuffer = securityBuffer;
               tlsClientSession.securityToken = std::string_view
               {
                  std::bit_cast<char const *>(securityBuffer),
                  tlsClientSession.wbioBufMem->length,
               };
            }
         }
         else if (errorCode == make_ssl_error_code(SSL_ERROR_WANT_READ))
         {
            tlsClientSession.securityBuffer = securityBuffer;
            tlsClientSession.securityToken = std::string_view
            {
               std::bit_cast<char const *>(tlsClientSession.securityBuffer),
               tlsClientSession.wbioBufMem->length,
            };
         }
         else
         {
            bytesProcessed = inboundDataChunk.bytesLength;
            tlsClientSession.wbioBufMem->length = 0;
            tlsClientSession.wbioBufMem->data = nullptr;
            tlsClientSession.wbioBufMem->max = 0;
            BIO_set_mem_buf(tlsClientSession.wbio, tlsClientSession.wbioBufMem, BIO_NOCLOSE);
            tlsClientSession.securityBuffer = nullptr;
            m_securityBuffersMemoryPool.push(securityBuffer);
            log_openssl_errors("[tls_client] failed to complete TLS handshake:");
            return errorCode;
         }
      }
      return {};
   }

   [[nodiscard]] std::string const &domain_name() const noexcept
   {
      return m_domainName;
   }

   [[nodiscard]] std::error_code encrypt_message(
      tls_client_session &session,
      data_chunk const dataChunk,
      size_t &bytesWritten
   )
   {
      assert(false && "Bad");
      (void)session;
      (void)dataChunk;
      (void)bytesWritten;
      return {};
   }

   void release_session(tls_client_session &tlsClientSession)
   {
      if (0 == SSL_clear(tlsClientSession.ssl.get())) [[unlikely]]
      {
         log_openssl_errors("[tls_client] failed to clear SSL structure:");
         unreachable();
      }
      if (nullptr != tlsClientSession.securityBuffer)
      {
         tlsClientSession.wbioBufMem->length = 0;
         tlsClientSession.wbioBufMem->data = nullptr;
         tlsClientSession.wbioBufMem->max = 0;
         BIO_set_mem_buf(tlsClientSession.wbio, tlsClientSession.wbioBufMem, BIO_NOCLOSE);
         m_securityBuffersMemoryPool.push(tlsClientSession.securityBuffer);
         tlsClientSession.securityBuffer = nullptr;
      }
      tlsClientSession.securityToken = std::string_view{"",};
      tlsClientSession.next = std::launder(m_tlsClientSessions);
      m_tlsClientSessions = std::launder(std::addressof(tlsClientSession));
   }

   [[nodiscard]] std::error_code shutdown(tls_client_session &tlsClientSession, data_chunk const &dataChunk, size_t &bytesWritten)
   {
      (void)dataChunk;
      (void)bytesWritten;
      if (tls_client_status::ready == tlsClientSession.status)
      {
         assert(false && "******************* shutdown");
      }
      else
      {
         bytesWritten = 0;
      }
      tlsClientSession.status = tls_client_status::none;
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
   std::unique_ptr<SSL_CTX> m_sslContext;
   memory_pool m_securityBuffersMemoryPool;
   tls_client_session *m_tlsClientSessions{nullptr,};
   std::string const m_domainName;
   memory_pool m_tlsClientSessionsMemoryPool;

   [[nodiscard]] static BIO *create_memory_bio()
   {
      auto *memoryBio{BIO_new(BIO_s_mem()),};
      if (nullptr == memoryBio) [[unlikely]]
      {
         log_openssl_errors("[tls_client] failed to create memory BIO:");
         unreachable();
      }
      return memoryBio;
   }
};

}
