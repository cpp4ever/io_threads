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
#include "windows/tls_client_session.hpp" ///< for io_threads::tls_client_session
#include "windows/wide_char.hpp" ///< for io_threads::utf8_to_wide_char
#include "windows/winapi_error.hpp" ///< for io_threads::check_winapi_error

/// for
///   APIENTRY,
///   BYTE,
///   CopyMemory,
///   DWORD,
///   FALSE,
///   GetModuleHandleA,
///   GetProcAddress,
///   PRTL_OSVERSIONINFOEXW,
///   RTL_OSVERSIONINFOEXW,
///   SEC_E_INCOMPLETE_MESSAGE,
///   SEC_E_OK,
///   SEC_I_CONTEXT_EXPIRED,
///   SEC_I_CONTINUE_NEEDED,
///   SEC_I_RENEGOTIATE,
///   ULONG,
///   ULONGLONG,
///   VER_BUILDNUMBER,
///   VER_GREATER_EQUAL,
///   VER_MAJORVERSION,
///   VER_MINORVERSION,
///   VER_PLATFORM_WIN32_NT,
///   VER_SERVICEPACKMAJOR,
///   VER_SET_CONDITION
#include <Windows.h>
#include <SubAuth.h> ///< for NTSTATUS, SCHANNEL_USE_BLACKLISTS, STATUS_SUCCESS
/// for
///   AcquireCredentialsHandleW,
///   ApplyControlToken,
///   CtxtHandle,
///   DeleteSecurityContext,
///   DecryptMessage,
///   EncryptMessage,
///   FreeContextBuffer,
///   FreeCredentialsHandle,
///   InitializeSecurityContextW,
///   ISC_REQ_ALLOCATE_MEMORY,
///   ISC_REQ_CONFIDENTIALITY,
///   ISC_REQ_DELEGATE,
///   ISC_REQ_EXTENDED_ERROR,
///   ISC_REQ_INTEGRITY,
///   ISC_REQ_MUTUAL_AUTH,
///   ISC_REQ_REPLAY_DETECT,
///   ISC_REQ_SEQUENCE_DETECT,
///   ISC_REQ_STREAM,
///   ISC_REQ_USE_SUPPLIED_CREDS,
///   PSecPkgInfoW,
///   QueryContextAttributesW,
///   QuerySecurityPackageInfoW,
///   SecBuffer,
///   SECBUFFER_ALERT,
///   SECBUFFER_DATA,
///   SECBUFFER_EMPTY,
///   SECBUFFER_EXTRA,
///   SECBUFFER_STREAM_HEADER,
///   SECBUFFER_STREAM_TRAILER,
///   SECBUFFER_TOKEN,
///   SECBUFFER_VERSION,
///   SecBufferDesc,
///   SECPKG_ATTR_STREAM_SIZES,
///   SECPKG_CRED_OUTBOUND,
///   SECPKG_FLAG_PRIVACY,
///   SECPKG_FLAG_STREAM,
///   SECURITY_NETWORK_DREP
#include <security.h>
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
///   CertFreeCertificateContext,
///   CertGetCertificateChain,
///   CertVerifyCertificateChainPolicy,
///   CredHandle,
///   CRYPT_DATA_BLOB,
///   HCERTCHAINENGINE,
///   HCERTSTORE,
///   PCCERT_CHAIN_CONTEXT,
///   PCCERT_CONTEXT,
///   PFXImportCertStore,
///   PKCS_7_ASN_ENCODING,
///   PKCS12_INCLUDE_EXTENDED_PROPERTIES,
///   PKCS12_NO_PERSIST_KEY,
///   SCH_CRED_AUTO_CRED_VALIDATION,
///   SCH_CRED_MANUAL_CRED_VALIDATION,
///   SCH_CRED_NO_DEFAULT_CREDS,
///   SCH_CRED_REVOCATION_CHECK_CHAIN,
///   SCH_CREDENTIALS,
///   SCH_CREDENTIALS_VERSION,
///   SCH_SEND_AUX_RECORD,
///   SCH_USE_STRONG_CRYPTO,
///   SCHANNEL_SHUTDOWN,
///   SP_PROT_TLS1_2_CLIENT,
///   SP_PROT_TLS1_3_CLIENT,
///   SSL_EXTRA_CERT_CHAIN_POLICY_PARA,
///   SSL_F12_EXTRA_CERT_CHAIN_POLICY_STATUS,
///   TLS_PARAMETERS,
///   UNISP_NAME_A,
///   UNISP_NAME_W,
///   USAGE_MATCH_TYPE_AND,
///   X509_ASN_ENCODING
#include <schannel.h>

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

#pragma comment(lib, "kernel32")
#pragma comment(lib, "ntdll")
#pragma comment(lib, "Secur32")

namespace io_threads
{

namespace
{

[[nodiscard]] static bool IsWindowsVersionOrGreater(
   DWORD const majorVersion,
   DWORD const minorVersion,
   DWORD const buildNumber
)
{
   static auto const RtlVerifyVersionInfo
   {
      std::bit_cast<
         NTSTATUS (APIENTRY *)(PRTL_OSVERSIONINFOEXW, ULONG, ULONGLONG)
      >(GetProcAddress(GetModuleHandleA("ntdll"), "RtlVerifyVersionInfo")),
   };
   RTL_OSVERSIONINFOEXW osVersionInfo
   {
      .dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW),
      .dwMajorVersion = majorVersion,
      .dwMinorVersion = minorVersion,
      .dwBuildNumber = buildNumber,
      .dwPlatformId = VER_PLATFORM_WIN32_NT,
      .szCSDVersion = {0},
      .wServicePackMajor = 0,
      .wServicePackMinor = 0,
      .wSuiteMask = 0,
      .wProductType = 0,
      .wReserved = 0,
   };
   ULONGLONG conditionMask{0,};
   VER_SET_CONDITION(conditionMask, VER_MAJORVERSION, VER_GREATER_EQUAL);
   VER_SET_CONDITION(conditionMask, VER_MINORVERSION, VER_GREATER_EQUAL);
   VER_SET_CONDITION(conditionMask, VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL);
   VER_SET_CONDITION(conditionMask, VER_BUILDNUMBER, VER_GREATER_EQUAL);
   return STATUS_SUCCESS == RtlVerifyVersionInfo(
      std::addressof(osVersionInfo),
      VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR | VER_BUILDNUMBER,
      conditionMask
   );
}

}

class tls_client_context::tls_client_context_impl final
{
public:
   tls_client_context_impl() = delete;
   tls_client_context_impl(tls_client_context_impl &&) = delete;
   tls_client_context_impl(tls_client_context_impl const &) = delete;

   [[nodiscard]] tls_client_context_impl(std::string_view const domainName, size_t const initialTlsClientSessionListCapacity) :
      m_sessionMemory
      {
         std::make_unique<memory_pool>(
            initialTlsClientSessionListCapacity,
            std::align_val_t{alignof(tls_client_session),},
            sizeof(tls_client_session)
         ),
      }
   {
      validate_environment(initialTlsClientSessionListCapacity);
      set_domain_name(domainName);
      acquire_credentials_handle();
   }

   [[nodiscard]] tls_client_context_impl(
      std::string_view const domainName,
      ssl_certificate const &sslCertificate,
      size_t const initialTlsClientSessionListCapacity
   ) :
      m_sessionMemory
      {
         std::make_unique<memory_pool>(
            initialTlsClientSessionListCapacity,
            std::align_val_t{alignof(tls_client_session),},
            sizeof(tls_client_session)
         ),
      }
   {
      validate_environment(initialTlsClientSessionListCapacity);
      set_domain_name(domainName);
      CRYPT_DATA_BLOB sslCertificateBlob
      {
         .cbData = static_cast<ULONG>(sslCertificate.content().size()),
         .pbData = std::bit_cast<BYTE *>(sslCertificate.content().data()),
      };
      std::wstring wcharPassword{};
      if (false == sslCertificate.password().empty())
      {
         if (auto const errorCode{utf8_to_wide_char(wcharPassword, sslCertificate.password()),}; true == bool{errorCode,}) [[unlikely]]
         {
            log_system_error(
               std::source_location::current(),
               "[tls_client] failed to convert password to wchar_t: ({}) - {}",
               errorCode
            );
            unreachable();
         }
      }
      m_certificateStore = PFXImportCertStore(
         std::addressof(sslCertificateBlob),
         wcharPassword.data(),
         PKCS12_INCLUDE_EXTENDED_PROPERTIES | PKCS12_NO_PERSIST_KEY
      );
      if (nullptr == m_certificateStore) [[unlikely]]
      {
         check_winapi_error("[tls_client] failed to import ssl certificates: ({}) - {}");
         unreachable();
      }
      m_certificateContext = CertFindCertificateInStore(
         m_certificateStore,
         X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
         0,
         CERT_FIND_SUBJECT_STR_W,
         m_domainName.first.data(),
         nullptr
      );
      if (nullptr == m_certificateContext)
      {
         check_winapi_error("[tls_client] failed to find certificate: ({}) - {}");
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
            m_certificateContext,
            nullptr,
            m_certificateContext->hCertStore,
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
         .pwszServerName = m_domainName.first.data(),
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
      acquire_credentials_handle();
   }

   ~tls_client_context_impl()
   {
      if (auto const returnCode{FreeCredentialsHandle(std::addressof(m_handle)),}; SEC_E_OK != returnCode) [[unlikely]]
      {
         log_system_error(
            std::source_location::current(),
            "[tls_client] failed to free credentials handle: ({:#X}) - {}",
            returnCode
         );
         m_handle = {};
      }
      if (nullptr != m_certificateContext)
      {
         CertFreeCertificateContext(m_certificateContext);
         m_certificateContext = nullptr;
      }
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

   tls_client_context_impl &operator = (tls_client_context_impl &&) = delete;
   tls_client_context_impl &operator = (tls_client_context_impl const &) = delete;

   [[nodiscard]] tls_client_session &acquire_session()
   {
      CtxtHandle securityContextHandle{.dwLower = 0, .dwUpper = 0,};
      auto const securityContextRequirements{security_context_requirements(),};
      auto &securityBuffer{pop_security_buffer(),};
      auto outboundSecurityBuffer
      {
         std::to_array(
            {
               SecBuffer
               {
                  .cbBuffer = static_cast<ULONG>(m_securityMemory->memory_size()),
                  .BufferType = SECBUFFER_TOKEN,
                  .pvBuffer = std::addressof(securityBuffer),
               },
            }
         ),
      };
      SecBufferDesc outboundSecurityBufferDescriptor
      {
         .ulVersion = SECBUFFER_VERSION,
         .cBuffers = static_cast<ULONG>(outboundSecurityBuffer.size()),
         .pBuffers = outboundSecurityBuffer.data(),
      };
      DWORD securityContextAttributes{0,};
      auto const returnCode
      {
         InitializeSecurityContextW(
            std::addressof(m_handle), ///< Credentials handle
            nullptr, ///< Existing security context handle
            m_domainName.first.data(), ///< Name of target
            securityContextRequirements, ///< Security context requirements
            0, ///< Reserved
            SECURITY_NETWORK_DREP, ///< Data representation
            nullptr, ///< Input buffers
            0, ///< Reserved
            std::addressof(securityContextHandle), ///< New security context handle
            std::addressof(outboundSecurityBufferDescriptor), ///< Output buffers
            std::addressof(securityContextAttributes), ///< Security context attributes
            nullptr ///< Expiration time of the security context
         )
      };
      if (SEC_I_CONTINUE_NEEDED == returnCode) [[likely]]
      {
         assert(0 < outboundSecurityBuffer[0].cbBuffer);
         assert(SECBUFFER_TOKEN == outboundSecurityBuffer[0].BufferType);
         assert(std::addressof(securityBuffer) <= outboundSecurityBuffer[0].pvBuffer);
         assert(
            (std::addressof(securityBuffer) + m_securityMemory->memory_size()) >= (std::bit_cast<std::byte const *>(outboundSecurityBuffer[0].pvBuffer) + outboundSecurityBuffer[0].cbBuffer)
         );
         return m_sessionMemory->pop_object<tls_client_session>(
            tls_client_session
            {
               .securityContextHandle = securityContextHandle,
               .status = tls_client_status::handshake,
               .securityBuffer = std::addressof(securityBuffer),
               .securityToken = std::string_view
               {
                  static_cast<char const *>(outboundSecurityBuffer[0].pvBuffer),
                  outboundSecurityBuffer[0].cbBuffer,
               },
            }
         );
      }
      log_system_error(
         std::source_location::current(),
         "[tls_client] failed to create security context: ({:#X}) - {}",
         returnCode
      );
      unreachable();
   }

   [[nodiscard]] std::error_code check_session_status(
      tls_client_session &session,
      data_chunk const dataChunk,
      size_t &bytesWritten
   )
   {
      bytesWritten = 0;
      if (nullptr != session.securityBuffer) [[unlikely]] ///< handshake or shutdown
      {
         if (true == session.securityToken.empty())
         {
            if (tls_client_status::handshake_complete == session.status) [[unlikely]]
            {
               session.status = tls_client_status::ready;
            }
            push_security_buffer(*session.securityBuffer);
            session.securityBuffer = nullptr;
            return {};
         }
         if (session.securityToken.size() > dataChunk.bytesLength) [[unlikely]]
         {
            log_error(
               std::source_location::current(),
               "[tls_client] {} byte send buffer is too small for {} byte security token",
               dataChunk.bytesLength,
               session.securityToken.size()
            );
            unreachable();
         }
         CopyMemory(dataChunk.bytes, session.securityToken.data(), session.securityToken.size());
         bytesWritten = session.securityToken.size();
         session.securityToken = std::string_view{"",};
         return {};
      }
      assert(true == session.securityToken.empty());
      return {};
   }

   [[nodiscard]] std::error_code decrypt_message(
      tls_client_session &session,
      data_chunk const inboundDataChunk,
      data_chunk &decryptedDataChunk,
      size_t &bytesProcessed
   )
   {
      decryptedDataChunk = {};
      if (tls_client_status::ready == session.status) [[likely]]
      {
         assert(nullptr == session.securityBuffer);
         auto securityBuffers
         {
            std::to_array(
               {
                  SecBuffer
                  {
                     .cbBuffer = static_cast<ULONG>(inboundDataChunk.bytesLength),
                     .BufferType = SECBUFFER_DATA,
                     .pvBuffer = std::bit_cast<void *>(inboundDataChunk.bytes),
                  },
                  SecBuffer{.cbBuffer = 0, .BufferType = SECBUFFER_EMPTY, .pvBuffer = nullptr,},
                  SecBuffer{.cbBuffer = 0, .BufferType = SECBUFFER_EMPTY, .pvBuffer = nullptr,},
                  SecBuffer{.cbBuffer = 0, .BufferType = SECBUFFER_EMPTY, .pvBuffer = nullptr,},
                  SecBuffer{.cbBuffer = 0, .BufferType = SECBUFFER_EMPTY, .pvBuffer = nullptr,},
               }
            )
         };
         SecBufferDesc securityBufferDescriptor
         {
            .ulVersion = SECBUFFER_VERSION,
            .cBuffers = static_cast<ULONG>(securityBuffers.size()),
            .pBuffers = securityBuffers.data(),
         };
         auto const returnCode
         {
            DecryptMessage(
               std::addressof(session.securityContextHandle),
               std::addressof(securityBufferDescriptor),
               0,
               nullptr
            ),
         };
         bytesProcessed = inboundDataChunk.bytesLength;
         std::error_code errorCode{};
         switch (returnCode)
         {
         [[likely]] case SEC_E_OK: [[fallthrough]];
         case SEC_I_RENEGOTIATE: [[fallthrough]];
         case SEC_I_CONTEXT_EXPIRED:
         {
            for (auto const &securityBuffer : securityBuffers)
            {
               switch (securityBuffer.BufferType)
               {
               case SECBUFFER_EMPTY:
               {
                  assert(0 == securityBuffer.cbBuffer);
                  assert(nullptr == securityBuffer.pvBuffer);
               }
               break;

               case SECBUFFER_DATA:
               {
                  assert(nullptr == decryptedDataChunk.bytes);
                  assert(0 == decryptedDataChunk.bytesLength);
                  decryptedDataChunk.bytes = std::bit_cast<std::byte *>(securityBuffer.pvBuffer);
                  decryptedDataChunk.bytesLength = securityBuffer.cbBuffer;
               }
               break;

               case SECBUFFER_EXTRA:
               {
                  if (inboundDataChunk.bytesLength < securityBuffer.cbBuffer) [[unlikely]]
                  {
                     log_error(
                        std::source_location::current(),
                        "[tls_client] data size check failed during decryption: expected {} bytes but actual size is {} bytes",
                        securityBuffer.cbBuffer,
                        inboundDataChunk.bytesLength
                     );
                     unreachable();
                  }
                  assert(inboundDataChunk.bytes <= securityBuffer.pvBuffer);
                  assert(
                     (std::bit_cast<std::byte const *>(securityBuffer.pvBuffer) + securityBuffer.cbBuffer) == (inboundDataChunk.bytes + inboundDataChunk.bytesLength)
                  );
                  if (SEC_I_RENEGOTIATE == returnCode)
                  {
                     size_t renegotiateBytesProcessed{0,};
                     session.status = tls_client_status::handshake;
                     errorCode = handle_handshake(
                        session,
                        data_chunk
                        {
                           .bytes = std::bit_cast<std::byte *>(securityBuffer.pvBuffer),
                           .bytesLength = static_cast<size_t>(securityBuffer.cbBuffer),
                        },
                        renegotiateBytesProcessed
                     );
                     assert(static_cast<size_t>(securityBuffer.cbBuffer) >= renegotiateBytesProcessed);
                     bytesProcessed -= static_cast<size_t>(securityBuffer.cbBuffer) - renegotiateBytesProcessed;
                  }
                  else
                  {
                     assert(SEC_E_OK == returnCode);
                     bytesProcessed -= securityBuffer.cbBuffer;
                  }
               }
               break;

               case SECBUFFER_STREAM_TRAILER: [[fallthrough]];
               case SECBUFFER_STREAM_HEADER: break;

               [[unlikely]] default:
               {
                  log_error(
                     std::source_location::current(),
                     "[tls_client] unexpected security buffer type {}",
                     securityBuffer.BufferType
                  );
                  unreachable();
               }
               }
            }
            if (SEC_I_CONTEXT_EXPIRED == returnCode) [[unlikely]]
            {
               errorCode = std::error_code{returnCode, std::system_category(),};
            }
         }
         break;

         [[unlikely]] case SEC_E_INCOMPLETE_MESSAGE:
         {
            bytesProcessed = 0;
         }
         break;

         [[unlikely]] default:
         {
            errorCode = std::error_code{returnCode, std::system_category(),};
            log_system_error(
               std::source_location::current(),
               "[tls_client] handshake failed: ({:#X}) - {}",
               errorCode
            );
         }
         break;
         }
         return errorCode;
      }
      else if (tls_client_status::handshake == session.status)
      {
         return handle_handshake(session, inboundDataChunk, bytesProcessed);
      }
      assert(tls_client_status::none == session.status);
      bytesProcessed = inboundDataChunk.bytesLength;
      return {};
   }

   [[nodiscard]] std::string_view domain_name() const noexcept
   {
      return m_domainName.second;
   }

   [[nodiscard]] std::error_code encrypt_message(
      tls_client_session &session,
      data_chunk const dataChunk,
      size_t &bytesWritten
   )
   {
      assert(tls_client_status::ready == session.status);
      assert(nullptr != dataChunk.bytes);
      assert(0 < dataChunk.bytesLength);
      auto const headerSize{session.streamSizes.cbHeader,};
      auto const trailerSize{session.streamSizes.cbTrailer,};
      if ((headerSize + bytesWritten + trailerSize) > dataChunk.bytesLength) [[unlikely]]
      {
         log_error(
            std::source_location::current(),
            "[tls_client] data size check failed during encryption: expected {} bytes but actual size is {} bytes",
            (headerSize + bytesWritten + trailerSize),
            dataChunk.bytesLength
         );
         unreachable();
      }
      auto securityBuffers
      {
         std::to_array(
            {
               SecBuffer
               {
                  .cbBuffer = headerSize,
                  .BufferType = SECBUFFER_STREAM_HEADER,
                  .pvBuffer = std::bit_cast<void *>(dataChunk.bytes),
               },
               SecBuffer
               {
                  .cbBuffer = static_cast<ULONG>(bytesWritten),
                  .BufferType = SECBUFFER_DATA,
                  .pvBuffer = std::bit_cast<void *>(dataChunk.bytes + headerSize),
               },
               SecBuffer
               {
                  .cbBuffer = trailerSize,
                  .BufferType = SECBUFFER_STREAM_TRAILER,
                  .pvBuffer = std::bit_cast<void *>(dataChunk.bytes + headerSize + bytesWritten),
               },
               SecBuffer{.cbBuffer = 0, .BufferType = SECBUFFER_EMPTY, .pvBuffer = nullptr,},
            }
         ),
      };
      SecBufferDesc securityBufferDescriptor
      {
         .ulVersion = SECBUFFER_VERSION,
         .cBuffers = static_cast<ULONG>(securityBuffers.size()),
         .pBuffers = securityBuffers.data(),
      };
      auto const returnCode
      {
         EncryptMessage(
            std::addressof(session.securityContextHandle),
            0,
            std::addressof(securityBufferDescriptor),
            0
         ),
      };
      bytesWritten = 0;
      std::error_code errorCode{};
      if (SEC_E_OK == returnCode) [[likely]]
      {
         for (auto const &securityBuffer : securityBuffers)
         {
            switch (securityBuffer.BufferType)
            {
            case SECBUFFER_EMPTY:
            {
               assert(0 == securityBuffer.cbBuffer);
               assert(nullptr == securityBuffer.pvBuffer);
            }
            break;

            case SECBUFFER_DATA: [[fallthrough]];
            case SECBUFFER_STREAM_TRAILER: [[fallthrough]];
            case SECBUFFER_STREAM_HEADER:
            {
               bytesWritten += securityBuffer.cbBuffer;
            }
            break;

            [[unlikely]] default:
            {
               log_error(
                  std::source_location::current(),
                  "[tls_client] unexpected security buffer type: {}",
                  securityBuffer.BufferType
               );
               unreachable();
            }
            }
         }
      }
      else
      {
         errorCode = std::error_code{returnCode, std::system_category(),};
         log_system_error(
            std::source_location::current(),
            "[tls_client] failed to encrypt message: ({:#X}) - {}",
            errorCode
         );
      }
      return errorCode;
   }

   void release_session(tls_client_session &session)
   {
      if (
         auto const returnCode{DeleteSecurityContext(std::addressof(session.securityContextHandle)),};
         SEC_E_OK != returnCode
      ) [[unlikely]]
      {
         log_system_error(
            std::source_location::current(),
            "[tls_client] failed to delete security context: ({:#X}) - {}",
            returnCode
         );
      }
      if (nullptr != session.securityBuffer)
      {
         push_security_buffer(*session.securityBuffer);
         session.securityBuffer = nullptr;
      }
      m_sessionMemory->push_object(session);
   }

   [[nodiscard]] std::error_code shutdown(tls_client_session &session, data_chunk const dataChunk, size_t &bytesWritten)
   {
      assert(tls_client_status::none != session.status);
      assert(nullptr != dataChunk.bytes);
      auto securityContextHandle{session.securityContextHandle,};
      auto const securityContextRequirements{security_context_requirements(),};
      DWORD schannelShutdown{SCHANNEL_SHUTDOWN,};
      auto inboundSecurityBuffers
      {
         std::to_array(
            {
               SecBuffer
               {
                  .cbBuffer = sizeof(schannelShutdown),
                  .BufferType = SECBUFFER_TOKEN,
                  .pvBuffer = std::addressof(schannelShutdown),
               },
            }
         ),
      };
      SecBufferDesc inboundSecurityBufferDescriptor
      {
         .ulVersion = SECBUFFER_VERSION,
         .cBuffers = static_cast<ULONG>(inboundSecurityBuffers.size()),
         .pBuffers = inboundSecurityBuffers.data(),
      };
      if (
         auto const returnCode{ApplyControlToken(std::addressof(securityContextHandle), std::addressof(inboundSecurityBufferDescriptor)),};
         SEC_E_OK != returnCode
      )
      {
         log_system_error(
            std::source_location::current(),
            "[tls_client] failed to apply control token: ({:#X}) - {}",
            returnCode
         );
         unreachable();
      }
      auto outboundSecurityBuffers
      {
         std::to_array({SecBuffer{.cbBuffer = 0, .BufferType = SECBUFFER_EMPTY, .pvBuffer = nullptr,},}),
      };
      SecBufferDesc outboundSecurityBufferDescriptor
      {
         .ulVersion = SECBUFFER_VERSION,
         .cBuffers = static_cast<ULONG>(outboundSecurityBuffers.size()),
         .pBuffers = outboundSecurityBuffers.data(),
      };
      DWORD securityContextAttributes{0,};
      auto const shutdownReturnCode
      {
         InitializeSecurityContextW(
            std::addressof(m_handle), ///< Credentials handle
            std::addressof(securityContextHandle), ///< Existing security context handle
            m_domainName.first.data(), ///< Name of target
            securityContextRequirements | ISC_REQ_ALLOCATE_MEMORY, ///< Security context requirements
            0, ///< Reserved
            SECURITY_NETWORK_DREP, ///< Data representation
            nullptr, ///< Input buffers
            0, ///< Reserved
            std::addressof(securityContextHandle), ///< New security context handle
            std::addressof(outboundSecurityBufferDescriptor), ///< Output buffers
            std::addressof(securityContextAttributes), ///< Security context attributes
            nullptr ///< Expiration time of the security context
         ),
      };
      assert(0 == std::memcmp(std::addressof(securityContextHandle), std::addressof(session.securityContextHandle), sizeof(CtxtHandle)));
      std::error_code errorCode{};
      if ((SEC_E_OK == shutdownReturnCode) || (SEC_I_CONTEXT_EXPIRED == shutdownReturnCode)) [[likely]]
      {
         bytesWritten = 0;
         for (auto const &outboundSecurityBuffer : outboundSecurityBuffers)
         {
            if (dataChunk.bytesLength < (bytesWritten + outboundSecurityBuffer.cbBuffer)) [[unlikely]]
            {
               log_error(
                  std::source_location::current(),
                  "[tls_client] data size check failed during shutdown: expected {} bytes but actual size is {} bytes",
                  (bytesWritten + outboundSecurityBuffer.cbBuffer),
                  dataChunk.bytesLength
               );
               unreachable();
            }
            CopyMemory(dataChunk.bytes + bytesWritten, outboundSecurityBuffer.pvBuffer, outboundSecurityBuffer.cbBuffer);
            bytesWritten += outboundSecurityBuffer.cbBuffer;
            if (auto const returnCode{FreeContextBuffer(outboundSecurityBuffer.pvBuffer),}; SEC_E_OK != returnCode) [[unlikely]]
            {
               log_system_error(
                  std::source_location::current(),
                  "[tls_client] failed to free memory buffers allocated by security context: ({:#X}) - {}",
                  returnCode
               );
            }
         }
      }
      else
      {
         errorCode = std::error_code{shutdownReturnCode, std::system_category(),};
         log_system_error(
            std::source_location::current(),
            "[tls_client] failed to shutdown: ({:#X}) - {}",
            errorCode
         );
      }
      session.status = tls_client_status::none;
      return errorCode;
   }

   [[nodiscard]] static size_t data_capacity(tls_client_session const &session, size_t const bytesCapacity)
   {
      assert(0 < session.streamSizes.cbMaximumMessage);
      auto const headerSize{session.streamSizes.cbHeader,};
      auto const trailerSize{session.streamSizes.cbTrailer,};
      if ((headerSize + 1 + trailerSize) > bytesCapacity) [[unlikely]]
      {
         log_error(
            std::source_location::current(),
            "[tls_client] a buffer of {} bytes is too small for an encrypted message of at least {} bytes",
            bytesCapacity,
            (headerSize + 1 + trailerSize)
         );
         unreachable();
      }
      return std::max<size_t>(bytesCapacity - headerSize - trailerSize, session.streamSizes.cbMaximumMessage);
   }

   [[nodiscard]] static size_t header_size(tls_client_session const &session, size_t) noexcept
   {
      assert(0 < session.streamSizes.cbMaximumMessage);
      return session.streamSizes.cbHeader;
   }

private:
   CredHandle m_handle{.dwLower = 0, .dwUpper = 0,};
   std::unique_ptr<memory_pool> m_securityMemory{nullptr,};
   std::unique_ptr<memory_pool> m_sessionMemory;
   std::pair<std::wstring, std::string> m_domainName;
   HCERTSTORE m_certificateStore{nullptr,};
   HCERTCHAINENGINE m_certificateChainEngine{nullptr,};
   PCCERT_CONTEXT m_certificateContext{nullptr,};

   void acquire_credentials_handle()
   {
      auto tlsParameters
      {
         std::to_array(
            {
               TLS_PARAMETERS
               {
                  .cAlpnIds = 0,
                  .rgstrAlpnIds = nullptr,
                  .grbitDisabledProtocols =
#if (defined(SP_PROT_TLS1_3_CLIENT))
                     ~(
                        DWORD{0,}
                           | SP_PROT_TLS1_2_CLIENT
                           /// Windows Server 2022 Version 21H2 and newer
                           | ((true == IsWindowsVersionOrGreater(10, 0, 20348)) ? SP_PROT_TLS1_3_CLIENT : 0)
                     )
#else
                     ~(DWORD{SP_PROT_TLS1_2_CLIENT,})
#endif
                  ,
                  .cDisabledCrypto = 0,
                  .pDisabledCrypto = nullptr,
                  .dwFlags = 0,
               },
            }
         ),
      };
      SCH_CREDENTIALS schannelCredentials
      {
         .dwVersion = SCH_CREDENTIALS_VERSION,
         .dwCredFormat = 0,
         .cCreds = static_cast<ULONG>((nullptr == m_certificateContext) ? 0 : 1),
         .paCred = ((nullptr == m_certificateContext) ? nullptr : std::addressof(m_certificateContext)),
         .hRootStore = m_certificateStore,
         .cMappers = 0,
         .aphMappers = nullptr,
         .dwSessionLifespan = 0,
         .dwFlags = DWORD{0,}
            | ((nullptr == m_certificateContext) ? DWORD{SCH_CRED_AUTO_CRED_VALIDATION,} : DWORD{SCH_CRED_MANUAL_CRED_VALIDATION,})
            | SCH_CRED_NO_DEFAULT_CREDS
            | SCH_CRED_REVOCATION_CHECK_CHAIN
            | SCH_SEND_AUX_RECORD
            | SCH_USE_STRONG_CRYPTO
         ,
         .cTlsParameters = static_cast<ULONG>(tlsParameters.size()),
         .pTlsParameters = tlsParameters.data(),
      };
      auto securityPackageName{std::to_array(UNISP_NAME_W),};
      if (
         auto const returnCode
         {
            AcquireCredentialsHandleW(
               nullptr,
               securityPackageName.data(),
               SECPKG_CRED_OUTBOUND,
               nullptr,
               std::addressof(schannelCredentials),
               nullptr,
               nullptr,
               std::addressof(m_handle),
               nullptr
            ),
         };
         SEC_E_OK != returnCode
      ) [[unlikely]]
      {
         log_system_error(
            std::source_location::current(),
            "[tls_client] failed to acquire credentials handle: ({:#X}) - {}",
            returnCode
         );
         unreachable();
      }
   }

   [[nodiscard]] std::error_code handle_handshake(
      tls_client_session &session,
      data_chunk const inboundDataChunk,
      size_t &bytesProcessed
   )
   {
      assert(tls_client_status::handshake == session.status);
      assert(nullptr == session.securityBuffer);
      assert(true == session.securityToken.empty());
      auto securityContextHandle{session.securityContextHandle,};
      auto const securityContextRequirements{security_context_requirements(),};
      auto inboundSecurityBuffers
      {
         std::to_array(
            {
               SecBuffer
               {
                  .cbBuffer = static_cast<ULONG>(inboundDataChunk.bytesLength),
                  .BufferType = SECBUFFER_TOKEN,
                  .pvBuffer = std::bit_cast<void *>(inboundDataChunk.bytes),
               },
               SecBuffer{.cbBuffer = 0, .BufferType = SECBUFFER_EMPTY, .pvBuffer = nullptr,},
            }
         ),
      };
      SecBufferDesc inboundSecurityBufferDescriptor
      {
         .ulVersion = SECBUFFER_VERSION,
         .cBuffers = static_cast<ULONG>(inboundSecurityBuffers.size()),
         .pBuffers = inboundSecurityBuffers.data(),
      };
      auto &tokenSecurityBuffer{pop_security_buffer(),};
      auto &alertSecurityBuffer{pop_security_buffer(),};
      auto outboundSecurityBuffers
      {
         std::to_array(
            {
               SecBuffer
               {
                  .cbBuffer = static_cast<ULONG>(m_securityMemory->memory_size()),
                  .BufferType = SECBUFFER_TOKEN,
                  .pvBuffer = std::addressof(tokenSecurityBuffer),
               },
               SecBuffer
               {
                  .cbBuffer = static_cast<ULONG>(m_securityMemory->memory_size()),
                  .BufferType = SECBUFFER_ALERT,
                  .pvBuffer = std::addressof(alertSecurityBuffer),
               },
               SecBuffer{.cbBuffer = 0, .BufferType = SECBUFFER_EMPTY, .pvBuffer = nullptr,},
            }
         ),
      };
      SecBufferDesc outboundSecurityBufferDescriptor
      {
         .ulVersion = SECBUFFER_VERSION,
         .cBuffers = static_cast<ULONG>(outboundSecurityBuffers.size()),
         .pBuffers = outboundSecurityBuffers.data(),
      };
      DWORD securityContextAttributes{0,};
      auto const returnCode
      {
         InitializeSecurityContextW(
            std::addressof(m_handle), ///< Credentials handle
            std::addressof(securityContextHandle), ///< Existing security context handle
            m_domainName.first.data(), ///< Name of target
            securityContextRequirements, ///< Security context requirements
            0, ///< Reserved
            SECURITY_NETWORK_DREP, ///< Data representation
            std::addressof(inboundSecurityBufferDescriptor), ///< Input buffers
            0, ///< Reserved
            std::addressof(securityContextHandle), ///< New security context handle
            std::addressof(outboundSecurityBufferDescriptor), ///< Output buffers
            std::addressof(securityContextAttributes), ///< Security context attributes
            nullptr ///< Expiration time of the security context
         ),
      };
      assert(0 == std::memcmp(std::addressof(securityContextHandle), std::addressof(session.securityContextHandle), sizeof(CtxtHandle)));
      std::error_code errorCode{};
      bytesProcessed = inboundDataChunk.bytesLength;
      switch (returnCode)
      {
      case SEC_E_OK:
      {
         bytesProcessed = handle_handshake_step(session, inboundDataChunk, inboundSecurityBuffers, outboundSecurityBuffers);
         handle_handshake_completion(session);
         session.status = (true == session.securityToken.empty()) ? tls_client_status::ready : tls_client_status::handshake_complete;
      }
      break;

      case SEC_I_CONTINUE_NEEDED:
      {
         bytesProcessed = handle_handshake_step(session, inboundDataChunk, inboundSecurityBuffers, outboundSecurityBuffers);
      }
      break;

      case SEC_E_INCOMPLETE_MESSAGE:
      {
         bytesProcessed = 0;
      }
      break;

      default:
      {
         errorCode = std::error_code{returnCode, std::system_category(),};
         log_system_error(
            std::source_location::current(),
            "[tls_client] handshake failed: ({:#X}) - {}",
            errorCode
         );
      }
      break;
      }
      if (true == session.securityToken.empty())
      {
         push_security_buffer(tokenSecurityBuffer);
      }
      else
      {
         session.securityBuffer = std::addressof(tokenSecurityBuffer);
      }
      push_security_buffer(alertSecurityBuffer);
      return errorCode;
   }

   void handle_handshake_completion(tls_client_session &session) const
   {
      if (
         auto const returnCode
         {
            QueryContextAttributesW(
               std::addressof(session.securityContextHandle),
               SECPKG_ATTR_STREAM_SIZES,
               std::addressof(session.streamSizes)
            ),
         };
         SEC_E_OK != returnCode
      ) [[unlikely]]
      {
         log_system_error(
            std::source_location::current(),
            "[tls_client] failed to query stream sizes: ({:#X}) - {}",
            returnCode
         );
         unreachable();
      }
      auto const tlsPacketSizeLimit{session.streamSizes.cbHeader + session.streamSizes.cbMaximumMessage + session.streamSizes.cbTrailer,};
      if (tls_packet_size_limit < tlsPacketSizeLimit) [[unlikely]]
      {
         log_error(
            std::source_location::current(),
            "[tls_client] maximum message size is greater than 18 KiB"
         );
         unreachable();
      }
   }

   [[nodiscard]] size_t handle_handshake_step(
      tls_client_session &session,
      data_chunk const inboundDataChunk,
      std::array<SecBuffer, 2> const &inboundSecurityBuffers,
      std::array<SecBuffer, 3> const &outboundSecurityBuffers
   )
   {
      auto bytesProcessed{inboundDataChunk.bytesLength,};
      for (auto const &inboundSecurityBuffer : inboundSecurityBuffers)
      {
         switch (inboundSecurityBuffer.BufferType)
         {
         case SECBUFFER_EMPTY:
         {
            assert(0 == inboundSecurityBuffer.cbBuffer);
            assert(nullptr == inboundSecurityBuffer.pvBuffer);
         }
         break;

         case SECBUFFER_TOKEN:
         {
            assert(inboundDataChunk.bytesLength == inboundSecurityBuffer.cbBuffer);
            assert(inboundDataChunk.bytes == inboundSecurityBuffer.pvBuffer);
         }
         break;

         case SECBUFFER_EXTRA:
         {
            if (inboundDataChunk.bytesLength < inboundSecurityBuffer.cbBuffer) [[unlikely]]
            {
               log_error(
                  std::source_location::current(),
                  "[tls_client] data size check failed during handshake: expected {} bytes but actual size is {} bytes",
                  inboundSecurityBuffer.cbBuffer,
                  inboundDataChunk.bytesLength
               );
               unreachable();
            }
            bytesProcessed -= inboundSecurityBuffer.cbBuffer;
         }
         break;

         [[unlikely]] default:
         {
            log_error(
               std::source_location::current(),
               "[tls_client] unexpected security buffer type {}",
               inboundSecurityBuffer.BufferType
            );
            unreachable();
         }
         }
      }
      for (auto const &outboundSecurityBuffer : outboundSecurityBuffers)
      {
         switch (outboundSecurityBuffer.BufferType)
         {
         case SECBUFFER_EMPTY:
         {
            assert(0 == outboundSecurityBuffer.cbBuffer);
            assert(nullptr == outboundSecurityBuffer.pvBuffer);
         }
         break;

         case SECBUFFER_TOKEN:
         {
            if (0 < outboundSecurityBuffer.cbBuffer) [[likely]]
            {
               session.securityToken = std::string_view
               {
                  std::bit_cast<char const *>(outboundSecurityBuffer.pvBuffer),
                  static_cast<size_t>(outboundSecurityBuffer.cbBuffer),
               };
            }
         }
         break;

         case SECBUFFER_ALERT:
         {
            assert(0 == outboundSecurityBuffer.cbBuffer);
         }
         break;

         [[unlikely]] default:
         {
            log_error(
               std::source_location::current(),
               "[tls_client] unexpected security buffer type {}",
               outboundSecurityBuffer.BufferType
            );
            unreachable();
         }
         }
      }
      return bytesProcessed;
   }

   [[nodiscard]] std::byte &pop_security_buffer()
   {
      assert(nullptr != m_securityMemory);
      return *m_securityMemory->pop();
   }

   void push_security_buffer(std::byte &value)
   {
      assert(nullptr != m_securityMemory);
      m_securityMemory->push(std::addressof(value));
   }

   [[nodiscard]] DWORD security_context_requirements() const noexcept
   {
      constexpr auto commonSecurityContextRequirements
      {
         DWORD{0}
            | ISC_REQ_CONFIDENTIALITY
            | ISC_REQ_DELEGATE
            | ISC_REQ_EXTENDED_ERROR
            | ISC_REQ_INTEGRITY
            | ISC_REQ_REPLAY_DETECT
            | ISC_REQ_SEQUENCE_DETECT
            | ISC_REQ_STREAM
         ,
      };
      return (nullptr == m_certificateContext)
         ? commonSecurityContextRequirements | ISC_REQ_MUTUAL_AUTH
         : commonSecurityContextRequirements | ISC_REQ_USE_SUPPLIED_CREDS
      ;
   }

   void set_domain_name(std::string_view const value)
   {
      if (auto const errorCode{utf8_to_wide_char(m_domainName.first, value),}; true == bool{errorCode}) [[unlikely]]
      {
         log_system_error(
            std::source_location::current(),
            "[tls_client] failed to convert domain name to wchar_t: ({}) - {}",
            errorCode
         );
         unreachable();
      }
      m_domainName.first.shrink_to_fit();
      m_domainName.second = value;
   }

   void validate_environment(size_t const initialSecurityTokenListCapacity)
   {
      auto securityPackageName{std::to_array(UNISP_NAME_W),};
      PSecPkgInfoW securityPackageInfo{nullptr,};
      if (
         auto const returnCode{QuerySecurityPackageInfoW(securityPackageName.data(), std::addressof(securityPackageInfo)),};
         (SEC_E_OK != returnCode) || (nullptr == securityPackageInfo)
      ) [[unlikely]]
      {
         log_system_error(
            std::source_location::current(),
            "[tls_client] failed to query security package info: ({:#X}) - {}",
            returnCode
         );
         unreachable();
      }
      assert((std::wstring_view{UNISP_NAME_W,}) == securityPackageInfo->Name);
      if (SECPKG_FLAG_PRIVACY != (SECPKG_FLAG_PRIVACY & securityPackageInfo->fCapabilities)) [[unlikely]]
      {
         log_error(
            std::source_location::current(),
            "[tls_client] {} does not support encruption/decryption",
            std::string_view{UNISP_NAME_A,}
         );
         unreachable();
      }
      if (SECPKG_FLAG_STREAM != (SECPKG_FLAG_STREAM & securityPackageInfo->fCapabilities)) [[unlikely]]
      {
         log_error(
            std::source_location::current(),
            "[tls_client] {} does not support TCP",
            std::string_view{UNISP_NAME_A,}
         );
         unreachable();
      }
      m_securityMemory = std::make_unique<memory_pool>(
         initialSecurityTokenListCapacity,
         std::align_val_t{alignof(std::byte),},
         std::max<size_t>(sizeof(void *), securityPackageInfo->cbMaxToken)
      );
      if (auto const returnCode{FreeContextBuffer(securityPackageInfo),}; SEC_E_OK != returnCode) [[unlikely]]
      {
         log_system_error(
            std::source_location::current(),
            "[tls_client] failed to free security package info: ({:#X}) - {}",
            returnCode
         );
      }
   }
};

}
