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

#include "common/tls_client_status.hpp" ///< for io_threads::tls_client_status
#include "io_threads/data_chunk.hpp" ///< for io_threads::data_chunk
#include "io_threads/tcp_client_thread.hpp" ///< for io_threads::tcp_client_thread
#include "io_threads/tls_client.hpp" ///< for io_threads::tls_client
#include "io_threads/tls_client_context.hpp" ///< for io_threads::tls_client_context
#include "io_threads/x509_store.hpp" ///< for io_threads::x509_store
#if (defined(IO_THREADS_OPENSSL))
#  include "openssl/tls_client_context_impl.hpp" ///< for io_threads::tls_client_context::tls_client_context_impl
#elif (defined(IO_THREADS_SCHANNEL))
#  include "windows/tls_client_context_impl.hpp" ///< for io_threads::tls_client_context::tls_client_context_impl
#endif

#include <cassert> ///< for assert
#include <cstddef> ///< for size_t
#include <cstdint> ///< for uint32_t
#include <memory> ///< for std::make_shared
#include <string_view> ///< for std::string_view
#include <system_error> ///< for std::error_code
#include <utility> ///< for std::move

namespace io_threads
{

tls_client_context::tls_client_context(tls_client_context &&rhs) noexcept = default;
tls_client_context::tls_client_context(tls_client_context const &rhs) noexcept = default;

tls_client_context::tls_client_context(
   tcp_client_thread executor,
   x509_store const &x509Store,
   std::string_view const &domainName,
   uint32_t const tlsSessionListCapacity
) :
   m_executor{std::move(executor),}
{
   m_executor.execute(
      [this, &x509Store, domainName, tlsSessionListCapacity] ()
      {
         m_impl = std::make_shared<tls_client_context_impl>(x509Store.m_impl, domainName, tlsSessionListCapacity);
      }
   );
   assert(nullptr != m_impl);
}

tls_client_context::~tls_client_context()
{
   if (nullptr != m_impl)
   {
      m_executor.execute(
         [this] ()
         {
            m_impl.reset();
         }
      );
      assert(nullptr == m_impl);
   }
}

std::string_view tls_client_context::domain_name() const noexcept
{
   return m_impl->domain_name();
}

tls_client::tls_client(tls_client_context tlsClientContext) noexcept :
   super{tlsClientContext.m_executor,},
   m_tlsClientContext{std::move(tlsClientContext),}
{}

tls_client::~tls_client() = default;

std::string_view tls_client::domain_name() const noexcept
{
   return m_tlsClientContext.m_impl->domain_name();
}

void tls_client::io_connected()
{
   assert(nullptr == m_tlsClientSession);
   m_tlsClientSession = std::addressof(m_tlsClientContext.m_impl->acquire_session());
}

void tls_client::io_disconnected(std::error_code const &)
{
   if (nullptr != m_tlsClientSession)
   {
      m_tlsClientContext.m_impl->release_session(*m_tlsClientSession);
      m_tlsClientSession = nullptr;
   }
}

std::error_code tls_client::io_data_to_send(data_chunk const &dataChunk, size_t &bytesWritten)
{
   assert(nullptr != dataChunk.bytes);
   assert(0 < dataChunk.bytesLength);
   assert(nullptr != m_tlsClientSession);
   if (
      auto const errorCode{m_tlsClientContext.m_impl->check_session_status(*m_tlsClientSession, dataChunk, bytesWritten),};
      (true == bool{errorCode,}) || (tls_client_status::ready != m_tlsClientSession->status)
   ) [[unlikely]]
   {
      return errorCode;
   }
   if (
      auto const errorCode{io_data_to_encrypt(tls_client_context_impl::prepare_to_encrypt(*m_tlsClientSession, dataChunk), bytesWritten),};
      (true == bool{errorCode,}) || (0 == bytesWritten)
   )
   {
      return errorCode;
   }
   return m_tlsClientContext.m_impl->encrypt_message(*m_tlsClientSession, dataChunk, bytesWritten);
}

std::error_code tls_client::io_data_to_shutdown(data_chunk const &dataChunk, size_t &bytesWritten)
{
   assert(nullptr != dataChunk.bytes);
   assert(0 < dataChunk.bytesLength);
   assert(nullptr != m_tlsClientSession);
   return m_tlsClientContext.m_impl->shutdown(*m_tlsClientSession, dataChunk, bytesWritten);
}

std::error_code tls_client::io_data_received(data_chunk const &encryptedDataChunk, size_t &bytesRead)
{
   auto *encryptedBytes = encryptedDataChunk.bytes;
   auto encryptedBytesLength = encryptedDataChunk.bytesLength;
   assert(nullptr != encryptedBytes);
   assert(0 < encryptedBytesLength);
   assert(nullptr != m_tlsClientSession);
   bytesRead = 0;
   auto const isHandshake{(tls_client_status::handshake == m_tlsClientSession->status) || (tls_client_status::handshake_complete == m_tlsClientSession->status),};
   while (0 < encryptedBytesLength)
   {
      data_chunk decrypredDataChunk{.bytes = nullptr, .bytesLength = 0,};
      size_t bytesProcessed{0,};
      if (
         auto const errorCode
         {
            m_tlsClientContext.m_impl->decrypt_message(
               *m_tlsClientSession,
               data_chunk{.bytes = encryptedBytes, .bytesLength = encryptedBytesLength,},
               decrypredDataChunk,
               bytesProcessed
            ),
         };
         true == bool{errorCode,}
      )
      {
         return errorCode;
      }
      if (0 == bytesProcessed)
      {
         break;
      }
      bytesRead += bytesProcessed;
      encryptedBytes += bytesProcessed;
      encryptedBytesLength -= bytesProcessed;
      if (0 < decrypredDataChunk.bytesLength) [[likely]]
      {
         assert(nullptr != decrypredDataChunk.bytes);
         if (auto const errorCode{io_data_decrypted(decrypredDataChunk),}; true == bool{errorCode,})
         {
            return errorCode;
         }
      }
   }
   if (
      true
      && (true == isHandshake)
      && (
         false
         || (tls_client_status::ready == m_tlsClientSession->status)
         || (false == m_tlsClientSession->securityToken.empty())
      )
   ) [[unlikely]]
   {
      ready_to_send();
   }
   return std::error_code{};
}

}
