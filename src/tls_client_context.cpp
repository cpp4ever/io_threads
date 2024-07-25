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

#include "tls_client_status.hpp" ///< for io_threads::tls_client_status
#if (defined(__APPLE__))
#  include "macos/tls_client_context_impl.hpp" ///< for io_threads::tls_client_context::tls_client_context_impl
#elif (defined(__linux__))
#  include "linux/tls_client_context_impl.hpp" ///< for io_threads::tls_client_context::tls_client_context_impl
#elif (defined(_WIN32) || defined(_WIN64))
#  include "windows/tls_client_context_impl.hpp" ///< for io_threads::tls_client_context::tls_client_context_impl
#endif

#include "io_threads/ssl_certificate.hpp" ///< for io_threads::ssl_certificate
#include "io_threads/tcp_client_thread.hpp" ///< for io_threads::tcp_client_thread
#include "io_threads/tls_client.hpp" ///< for io_threads::tls_client_context::tls_client
#include "io_threads/tls_client_context.hpp" ///< for io_threads::tls_client_context

#include <cassert> ///< for assert
#include <cstddef> ///< for size_t, std::byte
#include <memory> ///< for std::make_shared
#include <string_view> ///< for std::string_view

namespace io_threads
{

tls_client_context::tls_client_context(tls_client_context &&rhs) noexcept = default;
tls_client_context::tls_client_context(tls_client_context const &rhs) noexcept = default;

tls_client_context::tls_client_context(std::string_view const domainName, size_t const initialTlsClientSessionListCapacity) :
   m_impl(std::make_shared<tls_client_context_impl>(domainName, initialTlsClientSessionListCapacity))
{
   assert(nullptr != m_impl);
}

tls_client_context::tls_client_context(
   std::string_view const domainName,
   ssl_certificate const &sslCertificate,
   size_t const initialTlsClientSessionListCapacity
) :
   m_impl(std::make_shared<tls_client_context_impl>(domainName, sslCertificate, initialTlsClientSessionListCapacity))
{
   assert(nullptr != m_impl);
}

tls_client_context::~tls_client_context() = default;

tls_client_context &tls_client_context::operator = (tls_client_context &&rhs) noexcept = default;
tls_client_context &tls_client_context::operator = (tls_client_context const &rhs) = default;

tls_client_context::tls_client::tls_client(tcp_client_thread const &tcpClientThread, tls_client_context const &tlsClientContext) :
   super(tcpClientThread),
   m_context(tlsClientContext.m_impl)
{
   assert(nullptr != m_context);
}

tls_client_context::tls_client::~tls_client()
{
   assert(nullptr != m_context);
   if (nullptr != m_session)
   {
      m_context->release_session(*m_session);
   }
}

void tls_client_context::tls_client::io_connected()
{
   assert(nullptr != m_context);
   if (nullptr != m_session)
   {
      m_context->release_session(*m_session);
   }
   m_session = std::addressof(m_context->acquire_session());
}

size_t tls_client_context::tls_client::io_data_to_send(std::byte *bytes, size_t const bytesCapacity)
{
   assert(nullptr != bytes);
   assert(0 < bytesCapacity);
   assert(nullptr != m_session);
   assert(nullptr != m_context);
   if (
      auto const bytesLength = m_context->check_session_status(*m_session, bytes, bytesCapacity);
      tls_client_status::ready != m_session->status
   ) [[unlikely]]
   {
      return bytesLength;
   }
   auto const dataLength = io_data_to_encrypt(
      bytes + m_context->header_size(*m_session, bytesCapacity),
      m_context->data_capacity(*m_session, bytesCapacity)
   );
   return (0 < dataLength) ? m_context->encrypt_message(*m_session, bytes, dataLength, bytesCapacity) : 0;
}

size_t tls_client_context::tls_client::io_data_to_shutdown(std::byte *bytes, size_t const bytesCapacity)
{
   assert(nullptr != bytes);
   assert(0 < bytesCapacity);
   assert(nullptr != m_session);
   assert(nullptr != m_context);
   return m_context->shutdown(*m_session, bytes, bytesCapacity);
}

size_t tls_client_context::tls_client::io_data_received(
   std::byte const *bytes,
   size_t bytesLength
)
{
   assert(nullptr != bytes);
   assert(0 < bytesLength);
   assert(nullptr != m_session);
   assert(nullptr != m_context);
   size_t totalBytesProcessed = 0;
   auto const isHandshake = (tls_client_status::handshake == m_session->status);
   while (0 < bytesLength)
   {
      auto dataChunk = data_chunk{};
      auto const bytesProcessed = m_context->decrypt_message(
         *m_session,
         data_chunk{.bytes = std::bit_cast<std::byte *>(bytes), .bytesLength = bytesLength},
         dataChunk
      );
      if (tls_client_status::shutdown == m_session->status) [[unlikely]]
      {
         ready_to_disconnect();
         return bytesLength;
      }
      if (0 == bytesProcessed)
      {
         break;
      }
      totalBytesProcessed += bytesProcessed;
      bytes += bytesProcessed;
      bytesLength -= bytesProcessed;
      if (0 < dataChunk.bytesLength) [[likely]]
      {
         assert(nullptr != dataChunk.bytes);
         io_data_decrypted(dataChunk.bytes, dataChunk.bytesLength);
      }
   }
   if (
      (true == isHandshake) &&
      (
         (tls_client_status::ready == m_session->status) ||
         (false == m_session->securityToken.empty())
      )
   ) [[unlikely]]
   {
      ready_to_send();
   }
   return totalBytesProcessed;
}

std::error_code tls_client_context::tls_client::io_last_error() const
{
   assert(nullptr != m_context);
   return (nullptr == m_session) ? std::error_code{} : m_context->last_error(*m_session);
}

}
