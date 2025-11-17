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

#include "io_threads/data_chunk.hpp" ///< for io_threads::data_chunk
#include "io_threads/tcp_client.hpp" ///< for io_threads::tcp_client
#include "io_threads/tls_client_context.hpp" ///< for io_threads::tls_client_context

#include <cstddef> ///< for size_t
#include <cstdint> ///< for uint32_t
#include <memory> ///< for std::shared_ptr
#include <system_error> ///< for std::error_code

namespace io_threads
{

/// According to https://datatracker.ietf.org/doc/html/rfc5246#section-6.2.3
///   The length MUST NOT exceed 2^14 + 2048
[[maybe_unused]] constexpr uint32_t tls1_2_packet_size_limit{16384 + 2048,};

/// According to https://datatracker.ietf.org/doc/html/rfc8446#section-5.2
///   The length MUST NOT exceed 2^14 + 256 bytes
[[maybe_unused]] constexpr uint32_t tls1_3_packet_size_limit{16384 + 256,};

/// According to https://datatracker.ietf.org/doc/html/rfc8449#section-1
///   Allocating up to 18K of memory for ciphertext is beyond the capacity of some implementations
[[maybe_unused]] constexpr uint32_t tls_packet_size_limit{18432,};

struct tls_client_session;

class tls_client_context::tls_client : public tcp_client
{
private:
   using super = tcp_client;

public:
   tls_client() = delete;
   tls_client(tls_client &&) = delete;
   tls_client(tls_client const &) = delete;
   [[nodiscard]] explicit tls_client(tls_client_context tlsClientContext) noexcept;
   ~tls_client() override;

   tls_client &operator = (tls_client &&) = delete;
   tls_client &operator = (tls_client const &) = delete;

   [[maybe_unused, nodiscard]] tls_client_context const &context() const noexcept
   {
      return m_tlsClientContext;
   }

   [[nodiscard]] std::string_view domain_name() const noexcept;

protected:
   void io_connected() override;
   void io_disconnected(std::error_code const &errorCode) override;

private:
   tls_client_context const m_tlsClientContext;
   tls_client_session *m_tlsClientSession{nullptr};

   [[nodiscard]] virtual std::error_code io_data_decrypted(data_chunk const &dataChunk) = 0;
   [[nodiscard]] virtual std::error_code io_data_to_encrypt(data_chunk const &dataChunk, size_t &bytesWritten) = 0;
   [[nodiscard]] std::error_code io_data_to_send(data_chunk const &dataChunk, size_t &bytesWritten) final;
   [[nodiscard]] std::error_code io_data_to_shutdown(data_chunk const &dataChunk, size_t &bytesWritten) final;
   [[nodiscard]] std::error_code io_data_received(data_chunk const &dataChunk, size_t &bytesRead) final;
};

using tls_client [[maybe_unused]] = tls_client_context::tls_client;

[[nodiscard]] std::error_code make_tls_error_code(int value);
[[nodiscard]] std::error_code make_x509_error_code(int value);

[[nodiscard]] bool tls1_3_available();

}
