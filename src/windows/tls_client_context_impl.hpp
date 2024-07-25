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

#include "common/logger.hpp" ///< for io_threads::log_error
#include "common/object_pool.hpp" ///< for io_threads::object_pool
#include "common/tls_client_status.hpp" ///< for io_threads::tls_client_status
#include "common/utility.hpp" ///< for io_threads::unreachable
#include "io_threads/data_chunk.hpp" ///< for io_threads::data_chunk
#include "io_threads/ssl_certificate.hpp" ///< for io_threads::ssl_certificate
#include "io_threads/tls_client_context.hpp" ///< for io_threads::tls_client_context
#include "windows/tls_client_session.hpp" ///< for io_threads::tls_client_session
#include "windows/winapi_error.hpp" ///< for io_threads::check_winapi_error

/// for
///   DWORD,
///   SEC_E_OK
#include <Windows.h>
#include <SubAuth.h> ///< for SCHANNEL_USE_BLACKLISTS
/// for
///   AcquireCredentialsHandle,
///   FreeCredentialsHandle,
///   SECPKG_CRED_OUTBOUND
#include <security.h>
/// for
///   SCH_CRED_AUTO_CRED_VALIDATION,
///   SCH_CRED_NO_DEFAULT_CREDS,
///   SCH_USE_STRONG_CRYPTO,
///   SCH_CREDENTIALS,
///   SCH_CREDENTIALS_VERSION,
///   SP_PROT_TLS1_2_CLIENT,
///   SP_PROT_TLS1_3_CLIENT,
///   TLS_PARAMETERS,
///   UNISP_NAME
#include <schannel.h>

#include <array> ///< for std::to_array
#include <memory> ///< for std::addressof
#include <source_location> ///< for std::source_location
#include <string> ///< for std::string
#include <string_view> ///< for std::string_view
#include <utility> ///< for std::pair

#pragma comment(lib, "Secur32.lib")

namespace io_threads
{

class tls_client_context::tls_client_context_impl final
{
public:
   tls_client_context_impl() = delete;
   tls_client_context_impl(tls_client_context_impl &&) = delete;
   tls_client_context_impl(tls_client_context_impl const &) = delete;

   [[nodiscard]] tls_client_context_impl(std::string_view const domainName, size_t const initialTlsClientSessionListCapacity) :
      m_sessions(initialTlsClientSessionListCapacity)
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
      m_sessions(initialTlsClientSessionListCapacity)
   {
      validate_environment(initialTlsClientSessionListCapacity);
      set_domain_name(domainName);
      auto sslCertificateBlob = CRYPT_DATA_BLOB
      {
         .cbData = static_cast<ULONG>(sslCertificate.content().size()),
         .pbData = std::bit_cast<BYTE *>(sslCertificate.content().data()),
      };
      std::wstring wcharPassword;
      if (false == sslCertificate.password().empty())
      {
         wcharPassword.resize(sslCertificate.password().size() * 2);
         auto const wcharPasswordSize = MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            sslCertificate.password().data(),
            static_cast<int>(sslCertificate.password().size()),
            wcharPassword.data(),
            static_cast<int>(wcharPassword.size())
         );
         if (0 >= wcharPasswordSize) [[unlikely]]
         {
            check_winapi_error("[tls_client] failed to convert password to wchar_t: ({}) - {}");
            unreachable();
         }
         wcharPassword.resize(static_cast<size_t>(wcharPasswordSize));
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
      auto certificateChainEngineConfig = CERT_CHAIN_ENGINE_CONFIG
      {
         .cbSize = sizeof(CERT_CHAIN_ENGINE_CONFIG),
         .dwFlags = CERT_CHAIN_CACHE_END_CERT,
         .hExclusiveRoot = m_certificateStore,
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
      CERT_CHAIN_PARA certificateChainPara = {.cbSize = sizeof(CERT_CHAIN_PARA)};
      PCCERT_CHAIN_CONTEXT certificateChainContext = nullptr;
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
      auto certificateChainExtraPolicyPara = SSL_EXTRA_CERT_CHAIN_POLICY_PARA
      {
         .cbSize = sizeof(SSL_EXTRA_CERT_CHAIN_POLICY_PARA),
         .dwAuthType = AUTHTYPE_SERVER,
         .pwszServerName = m_domainName.first.data(),
      };
      auto certificateChainPolicyPara = CERT_CHAIN_POLICY_PARA
      {
         .cbSize = sizeof(CERT_CHAIN_POLICY_PARA),
         .pvExtraPolicyPara = std::addressof(certificateChainExtraPolicyPara),
      };
      auto certificateChainPolicyExtraStatus = SSL_F12_EXTRA_CERT_CHAIN_POLICY_STATUS
      {
         .cbSize = sizeof(SSL_F12_EXTRA_CERT_CHAIN_POLICY_STATUS),
      };
      auto certificateChainPolicyStatus = CERT_CHAIN_POLICY_STATUS
      {
         .cbSize = sizeof(CERT_CHAIN_POLICY_STATUS),
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
      if (auto const returnCode = FreeCredentialsHandle(std::addressof(m_handle)); SEC_E_OK != returnCode) [[unlikely]]
      {
         log_system_error(
            std::source_location::current(),
            "[tls_client] failed to free credentials handle: ({}) - {}",
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
      constexpr DWORD securityContextRequirements =
         ISC_REQ_CONFIDENTIALITY |
         ISC_REQ_EXTENDED_ERROR |
         ISC_REQ_INTEGRITY |
         ISC_REQ_REPLAY_DETECT |
         ISC_REQ_SEQUENCE_DETECT |
         ISC_REQ_STREAM |
         ISC_REQ_USE_SUPPLIED_CREDS
      ;
      CtxtHandle securityContextHandle = {};
      auto &securityBuffer = pop_security_buffer();
      auto outboundSecurityBuffer = std::to_array(
         {
            SecBuffer
            {
               .cbBuffer = static_cast<ULONG>(m_tokens->object_size()),
               .BufferType = SECBUFFER_TOKEN,
               .pvBuffer = std::addressof(securityBuffer),
            }
         }
      );
      auto outboundSecurityBufferDescriptor = SecBufferDesc
      {
         .ulVersion = SECBUFFER_VERSION,
         .cBuffers = static_cast<ULONG>(outboundSecurityBuffer.size()),
         .pBuffers = outboundSecurityBuffer.data(),
      };
      DWORD securityContextAttributes = 0;
      auto const returnCode = InitializeSecurityContextW(
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
      );
      if (SEC_I_CONTINUE_NEEDED == returnCode) [[likely]]
      {
         assert(0 < outboundSecurityBuffer[0].cbBuffer);
         assert(SECBUFFER_TOKEN == outboundSecurityBuffer[0].BufferType);
         assert(nullptr != outboundSecurityBuffer[0].pvBuffer);
         return m_sessions.pop(
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
               .securityContextRequirements = securityContextRequirements,
               .securityContextAttributes = securityContextAttributes,
            }
         );
      }
      log_system_error(
         std::source_location::current(),
         "[tls_client] failed to create security context: ({}) - {}",
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
            push_security_buffer(*session.securityBuffer);
            session.securityBuffer = nullptr;
            return {};
         }
         if (session.securityToken.size() > dataChunk.bytesLength) [[unlikely]]
         {
            log_error(
               std::source_location::current(),
               "[tls_client] send buffer ({} bytes) too small for security token ({} bytes)",
               dataChunk.bytesLength,
               m_tokens->object_size()
            );
            unreachable();
         }
         CopyMemory(dataChunk.bytes, session.securityToken.data(), session.securityToken.size());
         bytesWritten = session.securityToken.size();
         session.securityToken = {};
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
         auto securityBuffers = std::to_array(
            {
               SecBuffer
               {
                  .cbBuffer = static_cast<ULONG>(inboundDataChunk.bytesLength),
                  .BufferType = SECBUFFER_DATA,
                  .pvBuffer = std::bit_cast<void *>(inboundDataChunk.bytes),
               },
               SecBuffer{.BufferType = SECBUFFER_EMPTY},
               SecBuffer{.BufferType = SECBUFFER_EMPTY},
               SecBuffer{.BufferType = SECBUFFER_EMPTY},
               SecBuffer{.BufferType = SECBUFFER_EMPTY},
            }
         );
         auto securityBufferDescriptor = SecBufferDesc
         {
            .ulVersion = SECBUFFER_VERSION,
            .cBuffers = static_cast<ULONG>(securityBuffers.size()),
            .pBuffers = securityBuffers.data(),
         };
         auto const returnCode = DecryptMessage(std::addressof(session.securityContextHandle), std::addressof(securityBufferDescriptor), 0, nullptr);
         bytesProcessed = inboundDataChunk.bytesLength;
         std::error_code errorCode = {};
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
                  if (inboundDataChunk.bytesLength > securityBuffer.cbBuffer) [[unlikely]]
                  {
                     log_error(
                        std::source_location::current(),
                        "[tls_client] data size check failed during decryption: expected {} bytes but actual size is {} bytes",
                        securityBuffer.cbBuffer,
                        inboundDataChunk.bytesLength
                     );
                     unreachable();
                  }
                  if (SEC_I_RENEGOTIATE == returnCode)
                  {
                     session.securityBuffer = std::addressof(pop_security_buffer());
                     CopyMemory(session.securityBuffer, securityBuffer.pvBuffer, securityBuffer.cbBuffer);
                     session.securityToken = std::string_view{std::bit_cast<char const *>(session.securityBuffer), securityBuffer.cbBuffer};
                     session.status = tls_client_status::handshake;
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
               errorCode = std::error_code{returnCode, std::system_category()};
            }
            else if ((SEC_I_RENEGOTIATE == returnCode) && (tls_client_status::handshake != session.status)) [[unlikely]]
            {
               log_error(
                  std::source_location::current(),
                  "[tls_client] got renegotiate without extra data"
               );
               unreachable();
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
            errorCode = std::error_code{returnCode, std::system_category()};
            log_system_error(
               std::source_location::current(),
               "[tls_client] handshake failed: ({}) - {}",
               errorCode
            );
         }
         break;
         }
         return errorCode;
      }
      return handle_handshake(session, inboundDataChunk, bytesProcessed);
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
      auto const headerSize = session.streamSizes.cbHeader;
      auto const trailerSize = session.streamSizes.cbTrailer;
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
      auto securityBuffers = std::to_array(
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
            SecBuffer{.BufferType = SECBUFFER_EMPTY},
         }
      );
      auto securityBufferDescriptor = SecBufferDesc
      {
         .ulVersion = SECBUFFER_VERSION,
         .cBuffers = static_cast<ULONG>(securityBuffers.size()),
         .pBuffers = securityBuffers.data(),
      };
      auto const returnCode = EncryptMessage(std::addressof(session.securityContextHandle), 0, std::addressof(securityBufferDescriptor), 0);
      bytesWritten = 0;
      std::error_code errorCode = {};
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
         errorCode = std::error_code{returnCode, std::system_category()};
         log_system_error(
            std::source_location::current(),
            "[tls_client] failed to encrypt message: ({}) - {}",
            errorCode
         );
      }
      return errorCode;
   }

   void release_session(tls_client_session &session)
   {
      if (
         auto const returnCode = DeleteSecurityContext(std::addressof(session.securityContextHandle));
         SEC_E_OK != returnCode
      ) [[unlikely]]
      {
         log_system_error(
            std::source_location::current(),
            "[tls_client] failed to delete security context: ({}) - {}",
            returnCode
         );
      }
      if (nullptr != session.securityBuffer)
      {
         push_security_buffer(*session.securityBuffer);
         session.securityBuffer = nullptr;
      }
      m_sessions.push(session);
   }

   [[nodiscard]] std::error_code shutdown(tls_client_session &session, data_chunk const dataChunk, size_t &bytesWritten)
   {
      assert(tls_client_status::none != session.status);
      assert(nullptr != dataChunk.bytes);
      DWORD schannelShutdown = SCHANNEL_SHUTDOWN;
      auto inboundSecurityBuffers = std::to_array(
         {
            SecBuffer
            {
               .cbBuffer = sizeof(schannelShutdown),
               .BufferType = SECBUFFER_TOKEN,
               .pvBuffer = std::addressof(schannelShutdown),
            },
         }
      );
      auto inboundSecurityBufferDescriptor = SecBufferDesc
      {
         .ulVersion = SECBUFFER_VERSION,
         .cBuffers = static_cast<ULONG>(inboundSecurityBuffers.size()),
         .pBuffers = inboundSecurityBuffers.data(),
      };
      if (
         auto const returnCode = ApplyControlToken(std::addressof(session.securityContextHandle), std::addressof(inboundSecurityBufferDescriptor));
         SEC_E_OK != returnCode
      )
      {
         log_system_error(
            std::source_location::current(),
            "[tls_client] failed to apply control token: ({}) - {}",
            returnCode
         );
         unreachable();
      }
      auto outboundSecurityBuffers = std::to_array(
         {
            SecBuffer{.BufferType = SECBUFFER_EMPTY},
         }
      );
      auto outboundSecurityBufferDescriptor = SecBufferDesc
      {
         .ulVersion = SECBUFFER_VERSION,
         .cBuffers = static_cast<ULONG>(outboundSecurityBuffers.size()),
         .pBuffers = outboundSecurityBuffers.data()
      };
      auto const shutdownReturnCode = InitializeSecurityContextW(
         std::addressof(m_handle), ///< Credentials handle
         std::addressof(session.securityContextHandle), ///< Existing security context handle
         m_domainName.first.data(), ///< Name of target
         session.securityContextRequirements | ISC_REQ_ALLOCATE_MEMORY, ///< Security context requirements
         0, ///< Reserved
         SECURITY_NETWORK_DREP, ///< Data representation
         nullptr, ///< Input buffers
         0, ///< Reserved
         std::addressof(session.securityContextHandle), ///< New security context handle
         std::addressof(outboundSecurityBufferDescriptor), ///< Output buffers
         std::addressof(session.securityContextAttributes), ///< Security context attributes
         nullptr ///< Expiration time of the security context
      );
      std::error_code errorCode = {};
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
            if (auto const returnCode = FreeContextBuffer(outboundSecurityBuffer.pvBuffer); SEC_E_OK != returnCode) [[unlikely]]
            {
               log_system_error(
                  std::source_location::current(),
                  "[tls_client] failed to free memory buffers allocated by security context: ({}) - {}",
                  returnCode
               );
            }
         }
      }
      else
      {
         errorCode = std::error_code{shutdownReturnCode, std::system_category()};
         log_system_error(
            std::source_location::current(),
            "[tls_client] failed to shutdown: ({}) - {}",
            errorCode
         );
      }
      session.status = tls_client_status::none;
      return errorCode;
   }

   [[nodiscard]] static size_t data_capacity(tls_client_session const &session, size_t const bytesCapacity)
   {
      assert(0 < session.streamSizes.cbMaximumMessage);
      auto const headerSize = session.streamSizes.cbHeader;
      auto const trailerSize = session.streamSizes.cbTrailer;
      if ((headerSize + 1 + trailerSize) > bytesCapacity) [[unlikely]]
      {
         log_error(
            std::source_location::current(),
            "[tls_client] buffer capacity is too small for encrypted message: minimum is {} bytes but actual capacity is {} bytes",
            (headerSize + 1 + trailerSize),
            bytesCapacity
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
   CredHandle m_handle = {};
   object_pool<tls_client_session> m_sessions;
   std::unique_ptr<object_pool<std::byte>> m_tokens = {};
   DWORD m_securityPackageCapabilities = 0;
   std::pair<std::wstring, std::string> m_domainName;
   HCERTSTORE m_certificateStore = nullptr;
   HCERTCHAINENGINE m_certificateChainEngine = nullptr;
   PCCERT_CONTEXT m_certificateContext = nullptr;

   void acquire_credentials_handle()
   {
      auto tlsParameters = std::to_array(
         {
#if (defined(SP_PROT_TLS1_3_CLIENT))
            TLS_PARAMETERS{.grbitDisabledProtocols = ~static_cast<DWORD>(SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT)}
#else
            TLS_PARAMETERS{.grbitDisabledProtocols = ~static_cast<DWORD>(SP_PROT_TLS1_2_CLIENT)}
#endif
         }
      );
      auto schannelCred = SCH_CREDENTIALS
      {
         .dwVersion = SCH_CREDENTIALS_VERSION,
         .cCreds = static_cast<ULONG>((nullptr == m_certificateContext) ? 0 : 1),
         .paCred = (nullptr == m_certificateContext) ? nullptr : std::addressof(m_certificateContext),
         .hRootStore = m_certificateStore,
         .dwFlags =
            static_cast<DWORD>((nullptr == m_certificateContext) ? SCH_CRED_AUTO_CRED_VALIDATION : SCH_CRED_MANUAL_CRED_VALIDATION) |
            SCH_CRED_NO_DEFAULT_CREDS |
            CERT_CHAIN_REVOCATION_CHECK_CHAIN |
            SCH_SEND_AUX_RECORD |
            SCH_USE_STRONG_CRYPTO
         ,
         .cTlsParameters = static_cast<ULONG>(tlsParameters.size()),
         .pTlsParameters = tlsParameters.data(),
      };
      auto securityPackageName = std::to_array(UNISP_NAME_W);
      if (
         auto const returnCode = AcquireCredentialsHandleW(
            nullptr,
            securityPackageName.data(),
            SECPKG_CRED_OUTBOUND,
            nullptr,
            std::addressof(schannelCred),
            NULL,
            NULL,
            std::addressof(m_handle),
            NULL
         );
         SEC_E_OK != returnCode
      ) [[unlikely]]
      {
         log_system_error(
            std::source_location::current(),
            "[tls_client] failed to acquire credentials handle: ({}) - {}",
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
      bytesProcessed = inboundDataChunk.bytesLength;
      auto inboundSecurityBuffers = std::to_array(
         {
            SecBuffer
            {
               .cbBuffer = static_cast<ULONG>(inboundDataChunk.bytesLength),
               .BufferType = SECBUFFER_TOKEN,
               .pvBuffer = std::bit_cast<void *>(inboundDataChunk.bytes),
            },
            SecBuffer{.BufferType = SECBUFFER_EMPTY},
            SecBuffer{.BufferType = SECBUFFER_EMPTY},
            SecBuffer{.BufferType = SECBUFFER_EMPTY},
            SecBuffer{.BufferType = SECBUFFER_EMPTY},
         }
      );
      auto inboundSecurityBufferDescriptor = SecBufferDesc
      {
         .ulVersion = SECBUFFER_VERSION,
         .cBuffers = static_cast<ULONG>(inboundSecurityBuffers.size()),
         .pBuffers = inboundSecurityBuffers.data(),
      };
      session.securityBuffer = std::addressof(pop_security_buffer());
      auto &alertSecurityBuffer = pop_security_buffer();
      auto outboundSecurityBuffers = std::to_array(
         {
            SecBuffer
            {
               .cbBuffer = static_cast<ULONG>(m_tokens->object_size()),
               .BufferType = SECBUFFER_TOKEN,
               .pvBuffer = session.securityBuffer,
            },
            SecBuffer
            {
               .cbBuffer = static_cast<ULONG>(m_tokens->object_size()),
               .BufferType = SECBUFFER_ALERT,
               .pvBuffer = std::addressof(alertSecurityBuffer),
            },
            SecBuffer{.BufferType = SECBUFFER_EMPTY},
         }
      );
      auto outboundSecurityBufferDescriptor = SecBufferDesc
      {
         .ulVersion = SECBUFFER_VERSION,
         .cBuffers = static_cast<ULONG>(outboundSecurityBuffers.size()),
         .pBuffers = outboundSecurityBuffers.data()
      };
      auto const returnCode = InitializeSecurityContextW(
         std::addressof(m_handle), ///< Credentials handle
         std::addressof(session.securityContextHandle), ///< Existing security context handle
         m_domainName.first.data(), ///< Name of target
         session.securityContextRequirements, ///< Security context requirements
         0, ///< Reserved
         SECURITY_NETWORK_DREP, ///< Data representation
         std::addressof(inboundSecurityBufferDescriptor), ///< Input buffers
         0, ///< Reserved
         std::addressof(session.securityContextHandle), ///< New security context handle
         std::addressof(outboundSecurityBufferDescriptor), ///< Output buffers
         std::addressof(session.securityContextAttributes), ///< Security context attributes
         nullptr ///< Expiration time of the security context
      );
      std::error_code errorCode = {};
      switch (returnCode)
      {
      case SEC_E_OK:
      {
         handle_handshake_completion(session);
         bytesProcessed = handle_handshake_step(session, inboundDataChunk.bytesLength, outboundSecurityBuffers);
         session.status = tls_client_status::ready;
         if (true == session.securityToken.empty())
         {
            push_security_buffer(*session.securityBuffer);
            session.securityBuffer = nullptr;
         }
      }
      break;

      case SEC_I_CONTINUE_NEEDED:
      {
         bytesProcessed = handle_handshake_step(session, inboundDataChunk.bytesLength, outboundSecurityBuffers);
         if (true == session.securityToken.empty()) [[unlikely]]
         {
            log_error(std::source_location::current(), "[tls_client] no security token generated during handshake");
            errorCode = std::error_code{returnCode, std::system_category()};
         }
      }
      break;

      case SEC_E_INCOMPLETE_MESSAGE:
      {
         bytesProcessed = 0;
      }
      break;

      default:
      {
         errorCode = std::error_code{returnCode, std::system_category()};
         log_system_error(
            std::source_location::current(),
            "[tls_client] handshake failed: ({}) - {}",
            errorCode
         );
      }
      break;
      }
      push_security_buffer(alertSecurityBuffer);
      return errorCode;
   }

   void handle_handshake_completion(tls_client_session &session) const
   {
      assert(0 == session.streamSizes.cbMaximumMessage);
      if (
         auto const returnCode = QueryContextAttributes(
            std::addressof(session.securityContextHandle),
            SECPKG_ATTR_STREAM_SIZES,
            std::addressof(session.streamSizes)
         );
         SEC_E_OK != returnCode
      ) [[unlikely]]
      {
         log_system_error(
            std::source_location::current(),
            "[tls_client] failed to query stream sizes: ({}) - {}",
            returnCode
         );
         unreachable();
      }
      constexpr auto tls1_3_maximum_message_size = 16 * 1024;
      if (tls1_3_maximum_message_size > session.streamSizes.cbMaximumMessage) [[unlikely]]
      {
         log_error(
            std::source_location::current(),
            "[tls_client] maximum message size is less than 16 KiB"
         );
         unreachable();
      }
      //if (nullptr != m_certificateContext)
      //{
      //   PCCERT_CONTEXT certificateContext = nullptr;
      //   if (
      //      auto const returnCode = QueryContextAttributes(
      //         std::addressof(session.securityContextHandle),
      //         SECPKG_ATTR_REMOTE_CERT_CONTEXT,
      //         std::addressof(certificateContext)
      //      );
      //      SEC_E_OK != returnCode
      //   ) [[unlikely]]
      //   {
      //      log_system_error(
      //         std::source_location::current(),
      //         "[tls_client] failed to query server certificate: ({}) - {}",
      //         returnCode
      //      );
      //      unreachable();
      //   }
      //   CertFreeCertificateContext(certificateContext);
      //}
   }

   [[nodiscard]] size_t handle_handshake_step(
      tls_client_session &session,
      size_t const inboundBytesLength,
      std::array<SecBuffer, 3> const &outboundSecurityBuffers
   )
   {
      size_t bytesProcessed = inboundBytesLength;
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
            if (0 < outboundSecurityBuffer.cbBuffer)
            {
               session.securityToken = std::string_view
               {
                  std::bit_cast<char const *>(outboundSecurityBuffer.pvBuffer),
                  static_cast<size_t>(outboundSecurityBuffer.cbBuffer),
               };
            }
         }
         break;

         case SECBUFFER_EXTRA:
         {
            if (inboundBytesLength > outboundSecurityBuffer.cbBuffer) [[unlikely]]
            {
               log_error(
                  std::source_location::current(),
                  "[tls_client] data size check failed during handshake: expected {} bytes but actual size is {} bytes",
                  outboundSecurityBuffer.cbBuffer,
                  inboundBytesLength
               );
               unreachable();
            }
            bytesProcessed -= outboundSecurityBuffer.cbBuffer;
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
      assert(nullptr != m_tokens);
      return m_tokens->pop();
   }

   void push_security_buffer(std::byte &value)
   {
      assert(nullptr != m_tokens);
      m_tokens->push(value);
   }

   void set_domain_name(std::string_view const value)
   {
      m_domainName.first.resize(value.size() * 2);
      auto const wcharDomainNameSize = MultiByteToWideChar(
         CP_UTF8,
         MB_ERR_INVALID_CHARS,
         value.data(),
         static_cast<int>(value.size()),
         m_domainName.first.data(),
         static_cast<int>(m_domainName.first.size())
      );
      if (0 >= wcharDomainNameSize) [[unlikely]]
      {
         check_winapi_error("[tls_client] failed to convert domain name to wchar_t: ({}) - {}");
         unreachable();
      }
      m_domainName.first.resize(static_cast<size_t>(wcharDomainNameSize));
      m_domainName.first.shrink_to_fit();
      m_domainName.second = value;
   }

   void validate_environment(size_t const initialSecurityTokenListCapacity)
   {
      auto securityPackageName = std::to_array(UNISP_NAME);
      PSecPkgInfo securityPackageInfo = nullptr;
      if (
         auto const returnCode = QuerySecurityPackageInfo(securityPackageName.data(), std::addressof(securityPackageInfo));
         (SEC_E_OK != returnCode) || (nullptr == securityPackageInfo)
      ) [[unlikely]]
      {
         log_system_error(
            std::source_location::current(),
            "[tls_client] failed to query security package info: ({}) - {}",
            returnCode
         );
         unreachable();
      }
      assert(std::string_view{UNISP_NAME} == securityPackageInfo->Name);
      if (SECPKG_FLAG_PRIVACY != (SECPKG_FLAG_PRIVACY & securityPackageInfo->fCapabilities)) [[unlikely]]
      {
         log_error(
            std::source_location::current(),
            "[tls_client] {} does not support encruption/decryption",
            std::string_view{UNISP_NAME}
         );
         unreachable();
      }
      if (SECPKG_FLAG_STREAM != (SECPKG_FLAG_STREAM & securityPackageInfo->fCapabilities)) [[unlikely]]
      {
         log_error(
            std::source_location::current(),
            "[tls_client] {} does not support TCP",
            std::string_view{UNISP_NAME}
         );
         unreachable();
      }
      m_tokens = std::make_unique<object_pool<std::byte>>(
         initialSecurityTokenListCapacity,
         std::max<size_t>(sizeof(void *), securityPackageInfo->cbMaxToken)
      );
      m_securityPackageCapabilities = securityPackageInfo->fCapabilities;
      if (auto const returnCode = FreeContextBuffer(securityPackageInfo); SEC_E_OK != returnCode) [[unlikely]]
      {
         log_system_error(
            std::source_location::current(),
            "[tls_client] failed to free security package info: ({}) - {}",
            returnCode
         );
      }
   }
};

}
