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
#include "common/utility.hpp" ///< for io_threads::unreachable
#include "io_threads/x509_store.hpp" ///< for io_threads::x509_format, io_threads::x509_store, io_threads::x509_store_config
#include "windows/wide_char.hpp" ///< for io_threads::utf8_to_wide_char
#include "windows/winapi_error.hpp" ///< for io_threads::check_winapi_error

#include <Windows.h> ///< for BYTE, FALSE, ULONG
/// for
///   AUTHTYPE_SERVER,
///   CERT_CHAIN_CACHE_END_CERT,
///   CERT_CHAIN_ENGINE_CONFIG,
///   CERT_CHAIN_PARA,
///   CERT_CHAIN_POLICY_PARA,
///   CERT_CHAIN_POLICY_SSL,
///   CERT_CHAIN_POLICY_SSL_F12_NONE_CATEGORY,
///   CERT_CHAIN_POLICY_SSL_F12_SUCCESS_LEVEL,
///   CERT_CHAIN_POLICY_STATUS,
///   CERT_CHAIN_REVOCATION_CHECK_CHAIN,
///   CERT_CLOSE_STORE_CHECK_FLAG,
///   CERT_ENHKEY_USAGE,
///   CERT_FIND_SUBJECT_STR_W,
///   CERT_USAGE_MATCH,
///   CertCloseStore,
///   CertCreateCertificateChainEngine,
///   CertFindCertificateInStore,
///   CertFreeCertificateChain,
///   CertFreeCertificateChainEngine,
///   CertGetCertificateChain,
///   CertVerifyCertificateChainPolicy,
///   CRYPT_DATA_BLOB,
///   HCERTCHAINENGINE,
///   HCERTSTORE,
///   PCCERT_CHAIN_CONTEXT,
///   PCCERT_CONTEXT,
///   PFXImportCertStore,
///   PKCS_7_ASN_ENCODING,
///   PKCS12_INCLUDE_EXTENDED_PROPERTIES,
///   PKCS12_NO_PERSIST_KEY,
///   SSL_EXTRA_CERT_CHAIN_POLICY_PARA,
///   SSL_F12_EXTRA_CERT_CHAIN_POLICY_STATUS,
///   USAGE_MATCH_TYPE_AND,
///   X509_ASN_ENCODING
#include <wincrypt.h>

#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <memory> ///< for std::addressof
#include <source_location> ///< for std::source_location
#include <string> ///< for std::wstring
#include <string_view> ///< for std::string_view

#pragma comment(lib, "Crypt32")

namespace io_threads
{

class x509_store::x509_store_impl final
{
public:
   x509_store_impl() = delete;
   x509_store_impl(x509_store_impl &&) = delete;
   x509_store_impl(x509_store_impl const &) = delete;

   [[nodiscard]] explicit x509_store_impl(x509_store_config const &config) noexcept :
      m_revocationCheckEnabled{config.enableRevocationCheck,}
   {}

   [[nodiscard]] x509_store_impl(x509_store_config const &config, std::vector<domain_address> const &) noexcept :
      m_revocationCheckEnabled{config.enableRevocationCheck,}
   {}

   [[nodiscard]] x509_store_impl(
      std::string_view const &x509Data,
      [[maybe_unused]] x509_format const x509DataFormat,
      std::string_view const &x509DataPassword
   ) :
      m_revocationCheckEnabled{false,}
   {
      assert(false == x509Data.empty());
      assert(x509_format::p12 == x509DataFormat);
      CRYPT_DATA_BLOB x509DataBlob
      {
         .cbData = static_cast<ULONG>(x509Data.size()),
         .pbData = std::bit_cast<BYTE *>(x509Data.data()),
      };
      std::wstring wcharPassword{};
      if (false == x509DataPassword.empty())
      {
         if (auto const errorCode{utf8_to_wide_char(wcharPassword, x509DataPassword),}; true == bool{errorCode,}) [[unlikely]]
         {
            log_system_error("[tls_client] failed to convert password to wchar_t: ({}) - {}", errorCode);
            unreachable();
         }
      }
      m_certificateStore = PFXImportCertStore(
         std::addressof(x509DataBlob),
         wcharPassword.data(),
         PKCS12_INCLUDE_EXTENDED_PROPERTIES | PKCS12_NO_PERSIST_KEY
      );
      if (nullptr == m_certificateStore) [[unlikely]]
      {
         check_winapi_error("[tls_client] failed to import ssl certificates: ({}) - {}");
         unreachable();
      }
      CERT_CHAIN_ENGINE_CONFIG certificateChainEngineConfig
      {
         .cbSize = sizeof(CERT_CHAIN_ENGINE_CONFIG),
         .hRestrictedRoot = nullptr,
         .hRestrictedTrust = nullptr,
         .hRestrictedOther = nullptr,
         .cAdditionalStore = 0,
         .rghAdditionalStore = nullptr,
         .dwFlags = CERT_CHAIN_CACHE_END_CERT,
         .dwUrlRetrievalTimeout = 0,
         .MaximumCachedCertificates = 0,
         .CycleDetectionModulus = 0,
         .hExclusiveRoot = m_certificateStore,
         .hExclusiveTrustedPeople = nullptr,
         .dwExclusiveFlags = 0,
      };
      if (
         FALSE == CertCreateCertificateChainEngine(
            std::addressof(certificateChainEngineConfig),
            std::addressof(m_certificateChainEngine)
         )
      )
      {
         check_winapi_error("[tls_client] failed to create certificate chain engine: ({}) - {}");
         unreachable();
      }
   }

   ~x509_store_impl()
   {
      if (nullptr != m_certificateChainEngine)
      {
         CertFreeCertificateChainEngine(m_certificateChainEngine);
      }
      if (nullptr != m_certificateStore)
      {
         if (FALSE == CertCloseStore(m_certificateStore, CERT_CLOSE_STORE_CHECK_FLAG))
         {
            check_winapi_error("[tls_client] failed to close the certificate store: ({}) - {}");
         }
         m_certificateStore = nullptr;
      }
   }

   x509_store_impl &operator = (x509_store_impl &&) = delete;
   x509_store_impl &operator = (x509_store_impl const &) = delete;

   [[nodiscard]] bool revocation_check_enabled() const noexcept
   {
      return m_revocationCheckEnabled;
   }

   [[nodiscard]] PCCERT_CONTEXT make_certificate_context(std::wstring const &domainName) const
   {
      if (nullptr == m_certificateStore)
      {
         return nullptr;
      }
      PCCERT_CONTEXT certificateContext = CertFindCertificateInStore(
         m_certificateStore,
         X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
         0,
         CERT_FIND_SUBJECT_STR_W,
         domainName.data(),
         nullptr
      );
      if (nullptr == certificateContext)
      {
         check_winapi_error("[tls_client] failed to find certificate: ({}) - {}");
         unreachable();
      }
      assert(m_certificateStore == certificateContext->hCertStore);
      CERT_CHAIN_PARA certificateChainPara
      {
         .cbSize = sizeof(CERT_CHAIN_PARA),
         .RequestedUsage = CERT_USAGE_MATCH
         {
            .dwType = USAGE_MATCH_TYPE_AND,
            .Usage = CERT_ENHKEY_USAGE
            {
               .cUsageIdentifier = 0,
               .rgpszUsageIdentifier = nullptr,
            },
         },
      };
      PCCERT_CHAIN_CONTEXT certificateChainContext{nullptr,};
      if (
         FALSE == CertGetCertificateChain(
            m_certificateChainEngine,
            certificateContext,
            nullptr,
            certificateContext->hCertStore,
            std::addressof(certificateChainPara),
            CERT_CHAIN_CACHE_END_CERT | CERT_CHAIN_REVOCATION_CHECK_CHAIN,
            nullptr,
            std::addressof(certificateChainContext)
         )
      )
      {
         check_winapi_error("[tls_client] failed to get certificate chain: ({}) - {}");
         unreachable();
      }
      SSL_EXTRA_CERT_CHAIN_POLICY_PARA certificateChainExtraPolicyPara
      {
         .cbSize = sizeof(SSL_EXTRA_CERT_CHAIN_POLICY_PARA),
         .dwAuthType = AUTHTYPE_SERVER,
         .fdwChecks = 0,
         .pwszServerName = std::bit_cast<WCHAR *>(domainName.data()),
      };
      CERT_CHAIN_POLICY_PARA certificateChainPolicyPara
      {
         .cbSize = sizeof(CERT_CHAIN_POLICY_PARA),
         .dwFlags = 0,
         .pvExtraPolicyPara = std::addressof(certificateChainExtraPolicyPara),
      };
      SSL_F12_EXTRA_CERT_CHAIN_POLICY_STATUS certificateChainPolicyExtraStatus
      {
         .cbSize = sizeof(SSL_F12_EXTRA_CERT_CHAIN_POLICY_STATUS),
         .dwErrorLevel = CERT_CHAIN_POLICY_SSL_F12_SUCCESS_LEVEL,
         .dwErrorCategory = CERT_CHAIN_POLICY_SSL_F12_NONE_CATEGORY,
         .dwReserved = 0,
         .wszErrorText = {0,},
      };
      CERT_CHAIN_POLICY_STATUS certificateChainPolicyStatus
      {
         .cbSize = sizeof(CERT_CHAIN_POLICY_STATUS),
         .dwError = 0,
         .lChainIndex = 0,
         .lElementIndex = 0,
         .pvExtraPolicyStatus = std::addressof(certificateChainPolicyExtraStatus),
      };
      if (
         FALSE == CertVerifyCertificateChainPolicy(
            CERT_CHAIN_POLICY_SSL,
            certificateChainContext,
            std::addressof(certificateChainPolicyPara),
            std::addressof(certificateChainPolicyStatus)
         )
      )
      {
         log_error(
            std::source_location::current(),
            "[tls_client] failed to verify certificate chain: {}",
            certificateChainPolicyStatus.dwError
         );
         unreachable();
      }
      CertFreeCertificateChain(certificateChainContext);
      return certificateContext;
   }

private:
   HCERTSTORE m_certificateStore{nullptr,};
   HCERTCHAINENGINE m_certificateChainEngine{nullptr,};
   bool const m_revocationCheckEnabled;
};

}
