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

#define HAS_PREFIX(str, pre) (strncmp(str, pre "", sizeof(pre) - 1) == 0)

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
struct std::default_delete<SSL_CTX>
{
   constexpr default_delete() noexcept = default;
   constexpr default_delete(default_delete &&) noexcept = default;
   constexpr default_delete(default_delete const &) noexcept = default;

   constexpr default_delete &operator = (default_delete &&) noexcept = default;
   constexpr default_delete &operator = (default_delete const &) noexcept = default;

   void operator () (SSL_CTX *sslContext) const
   {
      SSL_CTX_free(sslContext);
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

template<>
struct std::default_delete<X509_VERIFY_PARAM>
{
   constexpr default_delete() noexcept = default;
   constexpr default_delete(default_delete &&) noexcept = default;
   constexpr default_delete(default_delete const &) noexcept = default;

   constexpr default_delete &operator = (default_delete &&) noexcept = default;
   constexpr default_delete &operator = (default_delete const &) noexcept = default;

   void operator () (X509_VERIFY_PARAM *x509VerifyParam) const
   {
      X509_VERIFY_PARAM_free(x509VerifyParam);
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

   [[nodiscard]] static const char *get_dp_url(DIST_POINT *dp)
   {
      GENERAL_NAMES *gens;
      GENERAL_NAME *gen;
      int i, gtype;
      ASN1_STRING *uri;

      if (!dp->distpoint || dp->distpoint->type != 0)
         return NULL;
      gens = dp->distpoint->name.fullname;
      for (i = 0; i < sk_GENERAL_NAME_num(gens); i++) {
         gen = sk_GENERAL_NAME_value(gens, i);
         uri = static_cast<ASN1_STRING *>(GENERAL_NAME_get0_value(gen, &gtype));
         if (gtype == GEN_URI && ASN1_STRING_length(uri) > 6) {
               const char *uptr = (const char *)ASN1_STRING_get0_data(uri);

               if (((uptr) != NULL && HAS_PREFIX(uptr, OSSL_HTTP_PREFIX))) /* can/should not use HTTPS here */
                  return uptr;
         }
      }
      return NULL;
   }

   [[nodiscard]] static X509_CRL *download_crl(const char *uri)
   {
      if (auto *x509Crl{X509_CRL_load_http(uri, nullptr, nullptr, 0),}; nullptr != x509Crl) [[likely]]
      {
         return x509Crl;
      }
      log_openssl_errors("[tls_client] failed to download CRL:");
      unreachable();
   }

   static X509_CRL *load_crl_crldp(STACK_OF(DIST_POINT) *crldp)
   {
      int i;
      const char *urlptr = NULL;

      for (i = 0; i < sk_DIST_POINT_num(crldp); i++) {
         DIST_POINT *dp = sk_DIST_POINT_value(crldp, i);

         urlptr = get_dp_url(dp);
         if (urlptr != NULL)
               return download_crl(urlptr);
      }
      return NULL;
   }

   static STACK_OF(X509_CRL) *load_crls(const X509_STORE_CTX *ctx)
   {
      X509 *x;
      STACK_OF(X509_CRL) *crls = NULL;
      X509_CRL *crl;
      STACK_OF(DIST_POINT) *crldp;

      crls = sk_X509_CRL_new_null();
      if (!crls)
         return NULL;
      x = X509_STORE_CTX_get_current_cert(ctx);
      crldp = static_cast<STACK_OF(DIST_POINT) *>(X509_get_ext_d2i(x, NID_crl_distribution_points, NULL, NULL));
      crl = load_crl_crldp(crldp);
      sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
      if (!crl) {
         sk_X509_CRL_free(crls);
         return NULL;
      }
      sk_X509_CRL_push(crls, crl);
      /* Try to download delta CRL */
      crldp = static_cast<STACK_OF(DIST_POINT) *>(X509_get_ext_d2i(x, NID_freshest_crl, NULL, NULL));
      crl = load_crl_crldp(crldp);
      sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
      if (crl)
         sk_X509_CRL_push(crls, crl);
      return crls;
   }

   static void verify_cert(X509_STORE *x509Store, std::string_view const commonName, bool const retry)
   {
      assert(nullptr != x509Store);
      auto *x509StoreContext{X509_STORE_CTX_new(),};
      assert(nullptr != x509StoreContext);
      if (0 == X509_STORE_CTX_init(x509StoreContext, x509Store, nullptr, nullptr)) [[unlikely]]
      {
         log_openssl_errors("[tls_client] failed to initialize X509_STORE_CTX:");
         unreachable();
      }
      auto *x509Name{X509_NAME_new(),};
      assert(nullptr != x509Name);
      if (
         0 == X509_NAME_add_entry_by_NID(
            x509Name,
            NID_commonName,
            MBSTRING_ASC,
            std::bit_cast<uint8_t const *>(commonName.data()),
            static_cast<int>(commonName.size()),
            -1,
            0
         )
      )
      {
         log_openssl_errors("[tls_client] failed to initialize X509_NAME:");
         unreachable();
      }
      auto *x509Object{X509_STORE_CTX_get_obj_by_subject(x509StoreContext, X509_LU_X509, x509Name),};
      if (nullptr == x509Object)
      {
         log_openssl_errors("[tls_client] failed to find X509:");
         unreachable();
      }
      assert(X509_LU_X509 == X509_OBJECT_get_type(x509Object));
      X509_STORE_CTX_set_cert(x509StoreContext, X509_OBJECT_get0_X509(x509Object));
      assert(nullptr != X509_STORE_CTX_get0_cert(x509StoreContext));
      if (1 == X509_STORE_CTX_verify(x509StoreContext)) [[likely]]
      {
         return;
      }
      if (auto const verifyError{X509_STORE_CTX_get_error(x509StoreContext),}; X509_V_ERR_UNABLE_TO_GET_CRL != verifyError) [[unlikely]]
      {
         log_openssl_errors("[tls_client] failed to validate cerificate:");
         return;
      }
      if (true == retry)
      {
         return;
      }
      auto *crls{load_crls(x509StoreContext)};
      if (nullptr == crls)
      {
         log_error(std::source_location::current(), "[tls_client] no CRLs loaded");
         unreachable();
      }
      for (int i = 0; i < sk_X509_CRL_num(crls); i++)
      {
         X509_STORE_add_crl(x509Store, sk_X509_CRL_value(crls, i));
      }
      verify_cert(x509Store, commonName, true);
   }

   [[nodiscard]] tls_client_context_impl(std::string_view const &domainName, size_t const capacityOfTlsClientSessionList) :
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
#if (defined(_WIN32) || defined(_WIN64))
      if (0 == SSL_CTX_load_verify_store(m_sslContext.get(), "org.openssl.winstore://"))
      {
         log_openssl_errors("[tls_client] failed to load org.openssl.winstore:");
         unreachable();
      }
#endif
      if (0 == SSL_CTX_enable_ct(m_sslContext.get(), SSL_CT_VALIDATION_PERMISSIVE)) [[unlikely]]
      {
         log_openssl_errors("[tls_client] failed to set TLS strict validation:");
         unreachable();
      }
      auto *x509Store{SSL_CTX_get_cert_store(m_sslContext.get()),};
      assert(nullptr != x509Store);
#if (not defined(_WIN32) && not defined(_WIN64))
      X509_STORE_set_default_paths(x509Store);
#endif
      X509_STORE_set_flags(
         x509Store,
         X509_V_FLAG_ALLOW_PROXY_CERTS | X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL | X509_V_FLAG_POLICY_CHECK | X509_V_FLAG_TRUSTED_FIRST | X509_V_FLAG_X509_STRICT
      );
      X509_STORE_set_purpose(x509Store, X509_PURPOSE_SSL_CLIENT);
      verify_cert(x509Store, m_domainName, false);
      std::unique_ptr<X509_VERIFY_PARAM> const x509VerifyParam{X509_VERIFY_PARAM_new(),};
      assert(nullptr != x509VerifyParam);
      X509_VERIFY_PARAM_set1_host(x509VerifyParam.get(), domainName.data(), domainName.size());
      X509_VERIFY_PARAM_set_auth_level(x509VerifyParam.get(), 2);
      X509_VERIFY_PARAM_set_flags(
         x509VerifyParam.get(),
         X509_V_FLAG_ALLOW_PROXY_CERTS | X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL | X509_V_FLAG_POLICY_CHECK | X509_V_FLAG_TRUSTED_FIRST | X509_V_FLAG_X509_STRICT
      );
      X509_VERIFY_PARAM_set_hostflags(x509VerifyParam.get(), X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT);
      X509_VERIFY_PARAM_set_purpose(x509VerifyParam.get(), X509_PURPOSE_SSL_CLIENT);
      SSL_CTX_set1_param(m_sslContext.get(), x509VerifyParam.get());
#if (not defined(_WIN32) && not defined(_WIN64))
      SSL_CTX_set_default_verify_paths(m_sslContext.get());
#endif
      SSL_CTX_set_min_proto_version(m_sslContext.get(), TLS1_2_VERSION);
      SSL_CTX_set_options(
         m_sslContext.get(),
         SSL_OP_NO_COMPRESSION | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1
      );
      SSL_CTX_set_post_handshake_auth(m_sslContext.get(), 1);
      SSL_CTX_set_tlsext_status_type(m_sslContext.get(), TLSEXT_STATUSTYPE_ocsp);
      SSL_CTX_set_security_level(m_sslContext.get(), 2);
      SSL_CTX_set_verify(m_sslContext.get(), SSL_VERIFY_PEER, nullptr);
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
         for (auto [bio, bioBufMem] : bioArray)
         {
            if (1 != BIO_set_mem_buf(bio, bioBufMem, BIO_NOCLOSE)) [[unlikely]]
            {
               log_openssl_errors("[tls_client] failed to setup empty memory BIO:");
               unreachable();
            }
         }
         m_tlsClientSessions = std::addressof(tlsClientSession);
      }
      assert(nullptr != m_tlsClientSessions);
   }

   [[nodiscard]] tls_client_context_impl(
      std::string_view const &domainName,
      ssl_certificate const &sslCertificate,
      size_t const capacityOfTlsClientSessionList
   ) :
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
      (void)sslCertificate;
      (void)capacityOfTlsClientSessionList;
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
      SSL_set_bio(tlsClientSession.ssl.get(), tlsClientSession.rbio, tlsClientSession.wbio);
      assert(tlsClientSession.rbio == SSL_get_rbio(tlsClientSession.ssl.get()));
      assert(tlsClientSession.wbio == SSL_get_wbio(tlsClientSession.ssl.get()));
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
            tlsClientSession.wbioBufMem->length = 0;
            tlsClientSession.wbioBufMem->data = nullptr;
            tlsClientSession.wbioBufMem->max = 0;
            BIO_set_mem_buf(tlsClientSession.wbio, tlsClientSession.wbioBufMem, BIO_NOCLOSE);
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
   std::unique_ptr<SSL_CTX> m_sslContext{create_ssl_context(),};
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

   [[nodiscard]] static SSL_CTX *create_ssl_context()
   {
      auto *sslContext{SSL_CTX_new(TLS_client_method()),};
      if (nullptr == sslContext) [[unlikely]]
      {
         log_openssl_errors("[tls_client] failed to create SSL context:");
         unreachable();
      }
      return sslContext;
   }
};

}
