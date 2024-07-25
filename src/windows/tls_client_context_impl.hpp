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
#include "io_threads/tls_client.hpp" ///< for io_threads::make_x509_error_code
#include "io_threads/tls_client_context.hpp" ///< for io_threads::tls_client_context
#include "windows/tls_client_session.hpp" ///< for io_threads::tls_client_session
#include "windows/wide_char.hpp" ///< for io_threads::utf8_to_wide_char
#include "windows/winapi_error.hpp" ///< for io_threads::check_winapi_error
#include "windows/x509_store_impl.hpp" ///< for io_threads::x509_store_impl

/// for
///   APIENTRY,
///   CertFreeCertificateContext,
///   CopyMemory,
///   DWORD,
///   GetModuleHandleA,
///   GetProcAddress,
///   PCCERT_CONTEXT,
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
#include <SubAuth.h> ///< for NTSTATUS, schannel.h, STATUS_SUCCESS
/// for
///   AcquireCredentialsHandleW,
///   ApplyControlToken,
///   CredHandle,
///   CtxtHandle,
///   DeleteSecurityContext,
///   DecryptMessage,
///   EncryptMessage,
///   FreeContextBuffer,
///   FreeCredentialsHandle,
///   InitializeSecurityContextW,
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
///   SCH_CRED_AUTO_CRED_VALIDATION,
///   SCH_CRED_MANUAL_CRED_VALIDATION,
///   SCH_CRED_NO_DEFAULT_CREDS,
///   SCH_CRED_REVOCATION_CHECK_CHAIN,
///   SCH_CREDENTIALS,
///   SCH_CREDENTIALS_VERSION,
///   SCH_SEND_AUX_RECORD,
///   SCH_USE_STRONG_CRYPTO,
///   SCHANNEL_SHUTDOWN,
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
///   SP_PROT_TLS1_2_CLIENT,
///   SP_PROT_TLS1_3_CLIENT,
///   TLS_PARAMETERS,
///   UNISP_NAME_A,
///   UNISP_NAME_W
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

class tls_client_context::tls_client_context_impl final
{
public:
   tls_client_context_impl() = delete;
   tls_client_context_impl(tls_client_context_impl &&) = delete;
   tls_client_context_impl(tls_client_context_impl const &) = delete;

   [[nodiscard]] tls_client_context_impl(
      std::shared_ptr<x509_store_impl> const &x509Store,
      std::string_view const domainName,
      size_t const tlsSessionListCapacity
   ) :
      m_sessionMemory
      {
         std::make_unique<memory_pool>(
            tlsSessionListCapacity,
            std::align_val_t{alignof(tls_client_session),},
            sizeof(tls_client_session)
         ),
      },
      m_x509Store{x509Store,}
   {
      assert(nullptr != m_x509Store);
      validate_environment(tlsSessionListCapacity);
      set_domain_name(domainName);
      acquire_credentials_handle();
   }

   ~tls_client_context_impl()
   {
      if (auto const returnCode{FreeCredentialsHandle(std::addressof(m_handle)),}; SEC_E_OK != returnCode) [[unlikely]]
      {
         log_system_error("[tls_client] failed to free credentials handle: ({:#X}) - {}", returnCode);
         m_handle = {.dwLower = 0, .dwUpper = 0,};
      }
      if (nullptr != m_certificateContext)
      {
         CertFreeCertificateContext(m_certificateContext);
         m_certificateContext = nullptr;
      }
   }

   tls_client_context_impl &operator = (tls_client_context_impl &&) = delete;
   tls_client_context_impl &operator = (tls_client_context_impl const &) = delete;

   [[nodiscard]] tls_client_session &acquire_session()
   {
      CtxtHandle securityContextHandle{.dwLower = 0, .dwUpper = 0,};
      auto const securityContextRequirements{security_context_requirements(),};
      auto *securityBuffer{m_securityMemory->pop_memory_chunk(),};
      auto outboundSecurityBuffer
      {
         std::to_array(
            {
               SecBuffer
               {
                  .cbBuffer = static_cast<ULONG>(m_securityMemory->memory_chunk_size()),
                  .BufferType = SECBUFFER_TOKEN,
                  .pvBuffer = securityBuffer,
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
         assert(securityBuffer <= outboundSecurityBuffer[0].pvBuffer);
         assert(
            (securityBuffer + m_securityMemory->memory_chunk_size()) >= (std::bit_cast<std::byte const *>(outboundSecurityBuffer[0].pvBuffer) + outboundSecurityBuffer[0].cbBuffer)
         );
         return m_sessionMemory->pop_object<tls_client_session>(
            tls_client_session
            {
               .securityContextHandle = securityContextHandle,
               .status = tls_client_status::handshake,
               .securityBuffer = securityBuffer,
               .securityToken = std::string_view
               {
                  static_cast<char const *>(outboundSecurityBuffer[0].pvBuffer),
                  outboundSecurityBuffer[0].cbBuffer,
               },
            }
         );
      }
      m_securityMemory->push_memory_chunk(securityBuffer);
      log_system_error("[tls_client] failed to create security context: ({:#X}) - {}", returnCode);
      unreachable();
   }

   [[nodiscard]] std::error_code check_session_status(
      tls_client_session &session,
      data_chunk const &dataChunk,
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
            m_securityMemory->push_memory_chunk(session.securityBuffer);
            session.securityBuffer = nullptr;
            return std::error_code{};
         }
         assert(session.securityToken.size() <= dataChunk.bytesLength);
         CopyMemory(dataChunk.bytes, session.securityToken.data(), session.securityToken.size());
         bytesWritten = session.securityToken.size();
         session.securityToken = std::string_view{"",};
         return std::error_code{};
      }
      assert(true == session.securityToken.empty());
      return std::error_code{};
   }

   [[nodiscard]] std::error_code decrypt_message(
      tls_client_session &session,
      data_chunk const &inboundDataChunk,
      data_chunk &decryptedDataChunk,
      size_t &bytesProcessed
   )
   {
      decryptedDataChunk = {.bytes = nullptr, .bytesLength = 0,};
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
                  assert(inboundDataChunk.bytesLength >= securityBuffer.cbBuffer);
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
                  log_error(std::source_location::current(), "[tls_client] unexpected security buffer type {}", securityBuffer.BufferType);
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
            log_system_error("[tls_client] decrypt failed: ({:#X}) - {}", errorCode);
            for (auto const &securityBuffer : securityBuffers)
            {
               if ((SECBUFFER_ALERT == securityBuffer.BufferType) && (0 < securityBuffer.cbBuffer))
               {
                  session.securityBuffer = m_securityMemory->pop_memory_chunk();
                  CopyMemory(session.securityBuffer, securityBuffer.pvBuffer, securityBuffer.cbBuffer);
                  session.securityToken = std::string_view
                  {
                     std::bit_cast<char const *>(session.securityBuffer),
                     static_cast<size_t>(securityBuffer.cbBuffer),
                  };
                  break;
               }
            }
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
      return std::error_code{};
   }

   [[nodiscard]] std::string const &domain_name() const noexcept
   {
      return m_domainName.second;
   }

   [[nodiscard]] std::error_code encrypt_message(
      tls_client_session &session,
      data_chunk const &dataChunk,
      size_t &bytesWritten
   )
   {
      assert(tls_client_status::ready == session.status);
      assert(nullptr != dataChunk.bytes);
      assert(0 < dataChunk.bytesLength);
      auto const headerSize{session.streamSizes.cbHeader,};
      auto const trailerSize{session.streamSizes.cbTrailer,};
      assert((headerSize + bytesWritten + trailerSize) <= dataChunk.bytesLength);
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
      auto const returnCode{EncryptMessage(std::addressof(session.securityContextHandle), 0, std::addressof(securityBufferDescriptor), 0),};
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
               log_error(std::source_location::current(), "[tls_client] unexpected security buffer type: {}", securityBuffer.BufferType);
               unreachable();
            }
            }
         }
      }
      else
      {
         errorCode = std::error_code{returnCode, std::system_category(),};
         log_system_error("[tls_client] failed to encrypt message: ({:#X}) - {}", errorCode);
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
         log_system_error("[tls_client] failed to delete security context: ({:#X}) - {}", returnCode);
      }
      if (nullptr != session.securityBuffer)
      {
         m_securityMemory->push_memory_chunk(session.securityBuffer);
         session.securityBuffer = nullptr;
      }
      m_sessionMemory->push_object(session);
   }

   [[nodiscard]] std::error_code shutdown(tls_client_session &session, data_chunk const &dataChunk, size_t &bytesWritten)
   {
      assert(tls_client_status::none != session.status);
      assert(nullptr != dataChunk.bytes);
      if (false == session.securityToken.empty())
      {
         assert(nullptr != session.securityBuffer);
         std::string_view const securityToken{session.securityToken,};
         session.securityToken = std::string_view{"",};
         CopyMemory(dataChunk.bytes, securityToken.data(), securityToken.size());
         bytesWritten = securityToken.size();
         return std::error_code{};
      }
      if (tls_client_status::handshake == session.status)
      {
         bytesWritten = 0;
         return std::error_code{};
      }
      auto securityContextHandle{session.securityContextHandle,};
      auto const securityContextRequirements{security_context_requirements(),};
      DWORD const schannelShutdown{SCHANNEL_SHUTDOWN,};
      CopyMemory(dataChunk.bytes, std::addressof(schannelShutdown), sizeof(schannelShutdown));
      auto inboundSecurityBuffers
      {
         std::to_array(
            {
               SecBuffer
               {
                  .cbBuffer = static_cast<ULONG>(dataChunk.bytesLength),
                  .BufferType = SECBUFFER_TOKEN,
                  .pvBuffer = dataChunk.bytes,
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
         log_system_error("[tls_client] failed to apply control token: ({:#X}) - {}", returnCode);
         unreachable();
      }
      auto outboundSecurityBuffers
      {
         std::to_array(
            {
               SecBuffer
               {
                  .cbBuffer = static_cast<ULONG>(dataChunk.bytesLength),
                  .BufferType = SECBUFFER_TOKEN,
                  .pvBuffer = dataChunk.bytes,
               },
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
      auto const shutdownReturnCode
      {
         InitializeSecurityContextW(
            std::addressof(m_handle), ///< Credentials handle
            std::addressof(securityContextHandle), ///< Existing security context handle
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
         ),
      };
      assert(0 == std::memcmp(std::addressof(securityContextHandle), std::addressof(session.securityContextHandle), sizeof(CtxtHandle)));
      std::error_code errorCode{};
      if ((SEC_E_OK == shutdownReturnCode) || (SEC_I_CONTEXT_EXPIRED == shutdownReturnCode)) [[likely]]
      {
         assert(1 == outboundSecurityBuffers.size());
         assert(dataChunk.bytes == outboundSecurityBuffers[0].pvBuffer);
         assert(dataChunk.bytesLength >= outboundSecurityBuffers[0].cbBuffer);
         bytesWritten = outboundSecurityBuffers[0].cbBuffer;
      }
      else
      {
         errorCode = std::error_code{shutdownReturnCode, std::system_category(),};
         log_system_error("[tls_client] failed to shutdown: ({:#X}) - {}", errorCode);
      }
      session.status = tls_client_status::none;
      return errorCode;
   }

   [[nodiscard]] static data_chunk prepare_to_encrypt(tls_client_session const &tlsClientSession, data_chunk const &dataChunk)
   {
      auto const streamSizes{tlsClientSession.streamSizes,};
      assert(0 < streamSizes.cbMaximumMessage);
      assert(nullptr != dataChunk.bytes);
      assert((streamSizes.cbHeader + streamSizes.cbBlockSize + streamSizes.cbTrailer) <= dataChunk.bytesLength);
      return data_chunk
      {
         .bytes = dataChunk.bytes + streamSizes.cbHeader,
         .bytesLength = std::max<size_t>(streamSizes.cbMaximumMessage, dataChunk.bytesLength - streamSizes.cbHeader - streamSizes.cbTrailer),
      };
   }

private:
   CredHandle m_handle{.dwLower = 0, .dwUpper = 0,};
   std::unique_ptr<memory_pool> m_securityMemory{nullptr,};
   std::unique_ptr<memory_pool> m_sessionMemory;
   std::pair<std::wstring, std::string> m_domainName;
   std::shared_ptr<x509_store_impl> const m_x509Store;
   PCCERT_CONTEXT m_certificateContext{nullptr,};

   void acquire_credentials_handle()
   {
      m_certificateContext = m_x509Store->make_certificate_context(m_domainName.first);
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
                           | ((true == tls1_3_available()) ? SP_PROT_TLS1_3_CLIENT : 0)
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
         .paCred = (nullptr == m_certificateContext) ? nullptr : std::addressof(m_certificateContext),
         .hRootStore = (nullptr == m_certificateContext) ? nullptr : m_certificateContext->hCertStore,
         .cMappers = 0,
         .aphMappers = nullptr,
         .dwSessionLifespan = 0,
         .dwFlags = DWORD{0,}
            | ((nullptr == m_certificateContext) ? DWORD{SCH_CRED_AUTO_CRED_VALIDATION,} : DWORD{SCH_CRED_MANUAL_CRED_VALIDATION,})
            | SCH_CRED_NO_DEFAULT_CREDS
            | ((true == m_x509Store->is_evocation_check_enabled()) ? DWORD{SCH_CRED_REVOCATION_CHECK_CHAIN,} : DWORD{0,})
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
         log_system_error("[tls_client] failed to acquire credentials handle: ({:#X}) - {}", returnCode);
         unreachable();
      }
   }

   [[nodiscard]] std::error_code handle_handshake(
      tls_client_session &session,
      data_chunk const &inboundDataChunk,
      size_t &bytesProcessed
   )
   {
      assert(tls_client_status::handshake == session.status);
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
      auto *tokenSecurityBuffer{(nullptr == session.securityBuffer) ? m_securityMemory->pop_memory_chunk() : session.securityBuffer,};
      auto *alertSecurityBuffer{m_securityMemory->pop_memory_chunk(),};
      auto outboundSecurityBuffers
      {
         std::to_array(
            {
               SecBuffer
               {
                  .cbBuffer = static_cast<ULONG>(m_securityMemory->memory_chunk_size()),
                  .BufferType = SECBUFFER_TOKEN,
                  .pvBuffer = tokenSecurityBuffer,
               },
               SecBuffer
               {
                  .cbBuffer = static_cast<ULONG>(m_securityMemory->memory_chunk_size()),
                  .BufferType = SECBUFFER_ALERT,
                  .pvBuffer = alertSecurityBuffer,
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
         if (true == session.securityToken.empty())
         {
            session.status = tls_client_status::ready;
            m_securityMemory->push_memory_chunk(tokenSecurityBuffer);
         }
         else
         {
            session.status = tls_client_status::handshake_complete;
            session.securityBuffer = tokenSecurityBuffer;
         }
         m_securityMemory->push_memory_chunk(alertSecurityBuffer);
         tokenSecurityBuffer = alertSecurityBuffer = nullptr;
      }
      break;

      case SEC_I_CONTINUE_NEEDED:
      {
         bytesProcessed = handle_handshake_step(session, inboundDataChunk, inboundSecurityBuffers, outboundSecurityBuffers);
         if (true == session.securityToken.empty())
         {
            m_securityMemory->push_memory_chunk(tokenSecurityBuffer);
         }
         else
         {
            session.securityBuffer = tokenSecurityBuffer;
         }
         m_securityMemory->push_memory_chunk(alertSecurityBuffer);
         tokenSecurityBuffer = alertSecurityBuffer = nullptr;
      }
      break;

      case SEC_E_INCOMPLETE_MESSAGE:
      {
         bytesProcessed = 0;
         m_securityMemory->push_memory_chunk(tokenSecurityBuffer);
         m_securityMemory->push_memory_chunk(alertSecurityBuffer);
         tokenSecurityBuffer = alertSecurityBuffer = nullptr;
      }
      break;

      default:
      {
         errorCode = std::error_code{returnCode, std::system_category(),};
         log_system_error("[tls_client] handshake failed: ({:#X}) - {}", errorCode);
         for (auto const &outboundSecurityBuffer : outboundSecurityBuffers)
         {
            if ((SECBUFFER_ALERT == outboundSecurityBuffer.BufferType) && (0 < outboundSecurityBuffer.cbBuffer))
            {
               session.securityBuffer = alertSecurityBuffer;
               CopyMemory(session.securityBuffer, outboundSecurityBuffer.pvBuffer, outboundSecurityBuffer.cbBuffer);
               session.securityToken = std::string_view
               {
                  std::bit_cast<char const *>(session.securityBuffer),
                  static_cast<size_t>(outboundSecurityBuffer.cbBuffer),
               };
               break;
            }
            else
            {
               assert(0 == outboundSecurityBuffer.cbBuffer);
            }
         }
         m_securityMemory->push_memory_chunk(tokenSecurityBuffer);
         if (true == session.securityToken.empty())
         {
            m_securityMemory->push_memory_chunk(alertSecurityBuffer);
         }
         tokenSecurityBuffer = alertSecurityBuffer = nullptr;
      }
      break;
      }
      assert(nullptr == tokenSecurityBuffer);
      assert(nullptr == alertSecurityBuffer);
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
         log_system_error("[tls_client] failed to query stream sizes: ({:#X}) - {}", returnCode);
         unreachable();
      }
      auto const tlsPacketSizeLimit{session.streamSizes.cbHeader + session.streamSizes.cbMaximumMessage + session.streamSizes.cbTrailer,};
      if (tls_packet_size_limit < tlsPacketSizeLimit) [[unlikely]]
      {
         log_error(std::source_location::current(), "[tls_client] maximum message size is greater than 18 KiB");
         unreachable();
      }
   }

   [[nodiscard]] size_t handle_handshake_step(
      tls_client_session &session,
      data_chunk const &inboundDataChunk,
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
            assert(inboundDataChunk.bytesLength >= inboundSecurityBuffer.cbBuffer);
            bytesProcessed -= inboundSecurityBuffer.cbBuffer;
         }
         break;

         [[unlikely]] default:
         {
            log_error(std::source_location::current(), "[tls_client] unexpected security buffer type {}", inboundSecurityBuffer.BufferType);
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
            log_error(std::source_location::current(), "[tls_client] unexpected security buffer type {}", outboundSecurityBuffer.BufferType);
            unreachable();
         }
         }
      }
      return bytesProcessed;
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

   void set_domain_name(std::string_view const &value)
   {
      if (auto const errorCode{utf8_to_wide_char(m_domainName.first, value),}; true == bool{errorCode}) [[unlikely]]
      {
         log_system_error("[tls_client] failed to convert domain name to wchar_t: ({}) - {}", errorCode);
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
         log_system_error("[tls_client] failed to query security package info: ({:#X}) - {}", returnCode);
         unreachable();
      }
      assert((std::wstring_view{UNISP_NAME_W,}) == securityPackageInfo->Name);
      if (SECPKG_FLAG_PRIVACY != (SECPKG_FLAG_PRIVACY & securityPackageInfo->fCapabilities)) [[unlikely]]
      {
         log_error(std::source_location::current(), "[tls_client] {} does not support encruption/decryption", std::string_view{UNISP_NAME_A,});
         unreachable();
      }
      if (SECPKG_FLAG_STREAM != (SECPKG_FLAG_STREAM & securityPackageInfo->fCapabilities)) [[unlikely]]
      {
         log_error(std::source_location::current(), "[tls_client] {} does not support TCP", std::string_view{UNISP_NAME_A,});
         unreachable();
      }
      m_securityMemory = std::make_unique<memory_pool>(
         initialSecurityTokenListCapacity,
         std::align_val_t{alignof(std::byte),},
         std::max<size_t>(sizeof(void *), securityPackageInfo->cbMaxToken)
      );
      if (auto const returnCode{FreeContextBuffer(securityPackageInfo),}; SEC_E_OK != returnCode) [[unlikely]]
      {
         log_system_error("[tls_client] failed to free security package info: ({:#X}) - {}", returnCode);
      }
   }
};

std::error_code make_tls_error_code(int const value)
{
   return std::error_code{value, std::system_category(),};
}

std::error_code make_x509_error_code(int const value)
{
   return std::error_code{value, std::system_category(),};
}

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

bool tls1_3_available()
{
   /// Windows Server 2022 Version 21H2 and newer
   return IsWindowsVersionOrGreater(10, 0, 20348);
}

}
