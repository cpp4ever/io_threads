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

#include "common/utility.hpp" ///< for io_threads::unreachable
#include "io_threads/x509_store.hpp" ///< for io_threads::x509_store, io_threads::x509_store_config
#include "openssl/error.hpp" ///< for io_threads::log_openssl_errors

#include <openssl/http.h>
/// for
///   SSL_CTX,
///   SSL_CTX_new,
///   SSL_CTX_set_cert_store
#include <openssl/ssl.h>
/// for
///   X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT,
///   X509_STORE,
///   X509_STORE_get0_param,
///   X509_STORE_new,
///   X509_STORE_set_default_paths,
///   X509_STORE_set_ex_data,
///   X509_STORE_set_flags,
///   X509_STORE_set_purpose,
///   X509_V_FLAG_CRL_CHECK,
///   X509_V_FLAG_CRL_CHECK_ALL,
///   X509_V_FLAG_EXTENDED_CRL_SUPPORT,
///   X509_V_FLAG_POLICY_CHECK,
///   X509_V_FLAG_SUITEB_192_LOS,
///   X509_V_FLAG_TRUSTED_FIRST,
///   X509_V_FLAG_USE_DELTAS,
///   X509_V_FLAG_X509_STRICT,
///   X509_VERIFY_PARAM_set_auth_level,
///   X509_VERIFY_PARAM_set_hostflags,
///   X509_VP_FLAG_RESET_FLAGS
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h> ///< for X509_PURPOSE_SSL_CLIENT

#include <cstdint> ///< for uint32_t
#include <cstring> ///< for std::memcpy
#include <map> ///< for std::map
#include <memory> ///< for std::default_delete, std::unique_ptr

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
struct std::default_delete<X509_CRL>
{
   constexpr default_delete() noexcept = default;
   constexpr default_delete(default_delete &&) noexcept = default;
   constexpr default_delete(default_delete const &) noexcept = default;

   constexpr default_delete &operator = (default_delete &&) noexcept = default;
   constexpr default_delete &operator = (default_delete const &) noexcept = default;

   void operator () (X509_CRL *x509Crl) const
   {
      X509_CRL_free(x509Crl);
   }
};

template<>
struct std::default_delete<X509_STORE>
{
   constexpr default_delete() noexcept = default;
   constexpr default_delete(default_delete &&) noexcept = default;
   constexpr default_delete(default_delete const &) noexcept = default;

   constexpr default_delete &operator = (default_delete &&) noexcept = default;
   constexpr default_delete &operator = (default_delete const &) noexcept = default;

   void operator () (X509_STORE *x509Store) const
   {
      X509_STORE_free(x509Store);
   }
};

namespace io_threads
{

class x509_store::x509_store_impl final
{
private:
   using map_url_to_x509_crl = std::map<std::string, std::unique_ptr<X509_CRL>, std::less<>>;

public:
   x509_store_impl() = delete;
   x509_store_impl(x509_store_impl &&) = delete;
   x509_store_impl(x509_store_impl const &) = delete;

   [[nodiscard]] explicit x509_store_impl(x509_store_config const &config) :
      m_enableCertificateVerification{config.enableCertificateVerification,}
   {
      if ((true == config.caDirectoryPath.empty()) && (true == config.caFilePath.empty()))
      {
         if (0 == X509_STORE_set_default_paths(m_x509Store.get())) [[unlikely]]
         {
            log_openssl_errors("[x509_store] failed to load from default CA paths");
            unreachable();
         }
      }
      else if (
         0 == X509_STORE_load_locations(
            m_x509Store.get(),
            (true == config.caFilePath.empty()) ? nullptr : config.caFilePath.string().data(),
            (true == config.caDirectoryPath.empty()) ? nullptr : config.caDirectoryPath.string().data()
         )
      ) [[unlikely]]
      {
         log_openssl_errors("[x509_store] failed to load from custom CA path");
         unreachable();
      }
      auto *x509VerifyParam{X509_STORE_get0_param(m_x509Store.get()),};
      assert(nullptr != x509VerifyParam);
      X509_VERIFY_PARAM_set_auth_level(x509VerifyParam, 2);
      uint32_t x509Flags{0,};
      if (true == config.enableRevocationCheck)
      {
         x509Flags |= X509_V_FLAG_CRL_CHECK;             ///< enable revocation check
         x509Flags |= X509_V_FLAG_CRL_CHECK_ALL;         ///< revocation checks for the entire certificate chain
         x509Flags |= X509_V_FLAG_EXTENDED_CRL_SUPPORT;  ///< enable check of additional CRL features
         x509Flags |= X509_V_FLAG_USE_DELTAS;            ///< use delta CRLs to determine certificate status
      }
      x509Flags |= X509_V_FLAG_POLICY_CHECK;             ///< enable policy check
      x509Flags |= X509_V_FLAG_TRUSTED_FIRST;            ///< should do nothing for default setup
      x509Flags |= X509_V_FLAG_X509_STRICT;              ///< disable workarounds
      X509_VERIFY_PARAM_set_flags(x509VerifyParam, x509Flags);
      X509_VERIFY_PARAM_set_inh_flags(x509VerifyParam, X509_VP_FLAG_RESET_FLAGS);
      X509_VERIFY_PARAM_set_hostflags(x509VerifyParam, X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT);
      X509_VERIFY_PARAM_set_purpose(x509VerifyParam, X509_PURPOSE_SSL_CLIENT);
      X509_VERIFY_PARAM_set_trust(x509VerifyParam, X509_TRUST_SSL_CLIENT);
   }

   [[nodiscard]] x509_store_impl(x509_store_config const &config, std::vector<domain_address> const &domainAddresses) :
      x509_store_impl{config,}
   {
      if (true == config.enableRevocationCheck)
      {
         auto sslContext{create_ssl_context(),};
         auto *x509VerifyParam{SSL_CTX_get0_param(sslContext.get()),};
         for (auto const &domainAddress : domainAddresses)
         {
            X509_VERIFY_PARAM_add1_host(x509VerifyParam, domainAddress.hostname.data(), domainAddress.hostname.size());
         }
         map_url_to_x509_crl mapUrlToX509Crl{};
         if (0 == X509_STORE_set_ex_data(m_x509Store.get(), 0, std::addressof(mapUrlToX509Crl)))
         {
            log_openssl_errors("[x509_store] failed to store downloaded CRLs");
            unreachable();
         }
         X509_STORE_set_lookup_crls(m_x509Store.get(), crls_lookup_callback);
         for (auto const &domainAddress : domainAddresses)
         {
            verify_certificate(sslContext.get(), domainAddress);
         }
         X509_STORE_set_lookup_crls(m_x509Store.get(), nullptr);
         X509_STORE_set_ex_data(m_x509Store.get(), 0, nullptr);
         /// Update the store cache with downloaded CRLs
         for (auto const &[url, x509Crl] : mapUrlToX509Crl)
         {
            if (nullptr != x509Crl)
            {
               add_crl_to_store(m_x509Store.get(), x509Crl.get());
            }
         }
      }
   }

   [[nodiscard]] x509_store_impl(
      std::string_view const &x509Data,
      [[maybe_unused]] x509_format const x509Format,
      std::string_view const &x509DataPassword
   ) :
      m_enableCertificateVerification{true,}
   {
      assert(false == x509Data.empty());
      assert(x509_format::pem == x509Format);
      auto *x509VerifyParam{X509_STORE_get0_param(m_x509Store.get()),};
      assert(nullptr != x509VerifyParam);
      uint32_t x509Flags{0,};
      x509Flags |= X509_V_FLAG_CHECK_SS_SIGNATURE; ///< Check self-signed CA signature
      x509Flags |= X509_V_FLAG_POLICY_CHECK;       ///< enable policy check
      x509Flags |= X509_V_FLAG_TRUSTED_FIRST;      ///< should do nothing for default setup
      x509Flags |= X509_V_FLAG_X509_STRICT;        ///< disable workarounds
      X509_VERIFY_PARAM_set_flags(x509VerifyParam, x509Flags);
      X509_VERIFY_PARAM_set_inh_flags(x509VerifyParam, X509_VP_FLAG_RESET_FLAGS);
      X509_VERIFY_PARAM_set_hostflags(x509VerifyParam, X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT);
      X509_VERIFY_PARAM_set_purpose(x509VerifyParam, X509_PURPOSE_SSL_CLIENT);
      X509_VERIFY_PARAM_set_trust(x509VerifyParam, X509_TRUST_SSL_CLIENT);
      BIO *bio{BIO_new_mem_buf(x509Data.data(), static_cast<int>(x509Data.size())),};
      auto *x509InfoStack = PEM_X509_INFO_read_bio(bio, nullptr, pem_password_callback, std::bit_cast<void *>(std::addressof(x509DataPassword)));
      for (int x509InfoIndex{0,}; sk_X509_INFO_num(x509InfoStack) > x509InfoIndex; ++x509InfoIndex)
      {
         if (auto *x509Info{sk_X509_INFO_value(x509InfoStack, x509InfoIndex),}; nullptr != x509Info)
         {
            if (nullptr != x509Info->x509)
            {
               add_certificate_to_store(m_x509Store.get(), x509Info->x509);
            }
            if (nullptr != x509Info->crl)
            {
               add_crl_to_store(m_x509Store.get(), x509Info->crl);
            }
         }
      }
      sk_X509_INFO_pop_free(x509InfoStack, X509_INFO_free);
      BIO_free(bio);
   }

   x509_store_impl &operator = (x509_store_impl &&) = delete;
   x509_store_impl &operator = (x509_store_impl const &) = delete;

   [[nodiscard]] std::unique_ptr<SSL_CTX> create_ssl_context()
   {
      std::unique_ptr<SSL_CTX> sslContext{SSL_CTX_new(TLS_client_method()),};
      SSL_CTX_set1_cert_store(sslContext.get(), m_x509Store.get());
      SSL_CTX_set1_param(sslContext.get(), SSL_CTX_get0_param(sslContext.get()));
      SSL_CTX_set_min_proto_version(sslContext.get(), TLS1_2_VERSION);
      SSL_CTX_set_options(
         sslContext.get(),
         SSL_OP_NO_COMPRESSION | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1
      );
      SSL_CTX_set_post_handshake_auth(sslContext.get(), 1);
      SSL_CTX_set_security_level(sslContext.get(), 2);
      SSL_CTX_set_tlsext_status_type(sslContext.get(), TLSEXT_STATUSTYPE_ocsp);
      SSL_CTX_set_verify(sslContext.get(), (true == m_enableCertificateVerification) ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, nullptr);
      return sslContext;
   }

private:
   bool const m_enableCertificateVerification;
   std::unique_ptr<X509_STORE> m_x509Store{create_x509_store(),};

   void verify_certificate(SSL_CTX *sslContext, domain_address const &domainAddress)
   {
      auto *bio{BIO_new_ssl_connect(sslContext),};
      BIO_set_conn_hostname(bio, domainAddress.hostname.data());
      auto const service{std::to_string(domainAddress.port),};
      BIO_set_conn_port(bio, service.data());
      SSL *ssl{nullptr,};
      BIO_get_ssl(bio, std::addressof(ssl));
      assert(nullptr != ssl);
      SSL_set_tlsext_host_name(ssl, domainAddress.hostname.data());
      BIO_do_connect(bio);
      BIO_free_all(bio);
   }

   static void add_certificate_to_store(X509_STORE *x509Store, X509 *x509)
   {
      assert(nullptr != x509Store);
      assert(nullptr != x509);
      if (0 == X509_STORE_add_cert(x509Store, x509)) [[unlikely]]
      {
         log_openssl_errors("[x509_store] failed to add certificate");
      }
   }

   static void add_crl_to_store(X509_STORE *x509Store, X509_CRL *x509Crl)
   {
      assert(nullptr != x509Store);
      assert(nullptr != x509Crl);
      if (0 == X509_STORE_add_crl(x509Store, x509Crl)) [[unlikely]]
      {
         log_openssl_errors("[x509_store] failed to add CRL");
      }
   }

   [[nodiscard]] static std::unique_ptr<X509_STORE> create_x509_store()
   {
      std::unique_ptr<X509_STORE> x509Store{X509_STORE_new(),};
      if (nullptr == x509Store) [[unlikely]]
      {
         log_openssl_errors("[x509_store] failed to create");
         unreachable();
      }
      if (0 == X509_STORE_set_purpose(x509Store.get(), X509_PURPOSE_SSL_CLIENT)) [[unlikely]]
      {
         log_openssl_errors("[x509_store] failed to set purpose");
         unreachable();
      }
      auto *x509VerifyParam{X509_STORE_get0_param(x509Store.get()),};
      assert(nullptr != x509VerifyParam);
      X509_VERIFY_PARAM_set_auth_level(x509VerifyParam, 2);
      X509_VERIFY_PARAM_set_hostflags(x509VerifyParam, X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT);
      X509_VERIFY_PARAM_set_purpose(x509VerifyParam, X509_PURPOSE_SSL_CLIENT);
      return x509Store;
   }

   [[nodiscard]] static STACK_OF(X509_CRL) *crls_lookup_callback(X509_STORE_CTX const *x509StoreContext, X509_NAME const *)
   {
      assert(nullptr != x509StoreContext);
      auto const *x509Store{X509_STORE_CTX_get0_store(x509StoreContext),};
      assert(nullptr != x509Store);
      auto *mapUrlToX509Crl{std::bit_cast<map_url_to_x509_crl *>(X509_STORE_get_ex_data(x509Store, 0)),};
      assert(nullptr != mapUrlToX509Crl);
      auto const *x509 = X509_STORE_CTX_get_current_cert(x509StoreContext);
      assert(nullptr != x509);
      auto *x509CrlStack{sk_X509_CRL_new_null(),};
      if (nullptr == x509CrlStack) [[unlikely]]
      {
         return nullptr;
      }
      download_crl(*mapUrlToX509Crl, x509CrlStack, x509, NID_crl_distribution_points);
      download_crl(*mapUrlToX509Crl, x509CrlStack, x509, NID_freshest_crl);
      return x509CrlStack;
   }

   static void download_crl(
      map_url_to_x509_crl &mapUrlToX509Crl,
      STACK_OF(X509_CRL) *x509CrlStack,
      X509 const *x509,
      int const NID
   )
   {
      auto *crlDistributionPointStack{static_cast<STACK_OF(DIST_POINT) *>(X509_get_ext_d2i(x509, NID, nullptr, nullptr)),};
      for (int crlDistributionPointIndex{0,}; sk_DIST_POINT_num(crlDistributionPointStack) > crlDistributionPointIndex; ++crlDistributionPointIndex)
      {
         if (
            auto const *crlDistributionPoint{sk_DIST_POINT_value(crlDistributionPointStack, crlDistributionPointIndex),};
            true
            && (nullptr != crlDistributionPoint)
            && (nullptr != crlDistributionPoint->distpoint)
            && (0 == crlDistributionPoint->distpoint->type)
         )
         {
            auto const *generalNameStack{crlDistributionPoint->distpoint->name.fullname};
            for (int generalNameIndex{0,}; sk_GENERAL_NAME_num(generalNameStack) > generalNameIndex; ++generalNameIndex)
            {
               download_crl(mapUrlToX509Crl, x509CrlStack, sk_GENERAL_NAME_value(generalNameStack, generalNameIndex));
            }
         }
      }
      sk_DIST_POINT_pop_free(crlDistributionPointStack, DIST_POINT_free);
   }

   static void download_crl(map_url_to_x509_crl &mapUrlToX509Crl, STACK_OF(X509_CRL) *x509CrlStack, GENERAL_NAME const *generalName)
   {
      if (nullptr == generalName) [[unlikely]]
      {
         return;
      }
      int generalNameType{0,};
      if (
         auto const *generalNameValue{static_cast<ASN1_STRING *>(GENERAL_NAME_get0_value(generalName, std::addressof(generalNameType))),};
         true
         && (nullptr != generalNameValue)
         && (GEN_URI == generalNameType)
         && (static_cast<int>(sizeof(OSSL_HTTP_PREFIX)) < ASN1_STRING_length(generalNameValue))
      )
      {
         if (
            auto const *uri = std::bit_cast<char const *>(ASN1_STRING_get0_data(generalNameValue));
            (nullptr != uri) && (0 == strncmp(uri, OSSL_HTTP_PREFIX, sizeof(OSSL_HTTP_PREFIX) - 1))
         )
         {
            download_crl(mapUrlToX509Crl, x509CrlStack, std::string{uri,});
         }
      }
   }

   static void download_crl(map_url_to_x509_crl &mapUrlToX509Crl, STACK_OF(X509_CRL) *x509CrlStack, std::string const &url)
   {
      auto &x509Crl{mapUrlToX509Crl[url],};
      if (nullptr == x509Crl)
      {
         x509Crl = download_crl(url);
      }
      if (nullptr != x509Crl)
      {
         push_x509_crl(x509CrlStack, x509Crl.get());
      }
   }

   [[nodiscard]] static std::unique_ptr<X509_CRL> download_crl(std::string const &url)
   {
      BIO *crlRequest
      {
         OSSL_HTTP_get(
            url.data(),
            nullptr, ///< proxy
            nullptr, ///< no_proxy
            nullptr, ///< bio
            nullptr, ///< rbio
            nullptr, ///< bio_update_fn
            nullptr, ///< arg
            10 * 1024, ///<< buf_size
            nullptr, ///< headers
            nullptr, ///< expected_content_type
            1, ///< expect_asn1
            32 * 1024 * 1024, ///< max_resp_len = 32MiB
            0 ///< timeout
         ),
      };
      if (nullptr == crlRequest)
      {
         log_openssl_errors("[x509_store] failed to download CRL");
         return nullptr;
      }
      auto *x509Crl{static_cast<X509_CRL *>(ASN1_item_d2i_bio(ASN1_ITEM_rptr(X509_CRL), crlRequest, nullptr)),};
      if (nullptr == x509Crl) [[unlikely]]
      {
         log_openssl_errors("[x509_store] failed to deserialize CRL");
      }
      BIO_free(crlRequest);
      return std::unique_ptr<X509_CRL>{x509Crl,};
   }

   [[nodiscard]] static int pem_password_callback(char *passwordBuffer, int const passwordBufferSize, int const, void *userdata)
   {
      assert(nullptr != passwordBuffer);
      assert(0 < passwordBufferSize);
      assert(nullptr != userdata);
      auto const &password = *std::bit_cast<std::string_view const *>(userdata);
      auto const passwordLength{std::min(static_cast<size_t>(passwordBufferSize - 1), password.size()),};
      std::memcpy(passwordBuffer, password.data(), passwordLength);
      passwordBuffer[passwordLength] = 0;
      return static_cast<int>(passwordLength);
   }

   static void push_x509_crl(STACK_OF(X509_CRL) *x509CrlStack, X509_CRL *x509Crl)
   {
      if (0 == X509_CRL_up_ref(x509Crl))
      {
         log_openssl_errors("[x509_store] failed to increment CRL ref count");
         unreachable();
      }
      sk_X509_CRL_push(x509CrlStack, x509Crl);
   }
};

}
