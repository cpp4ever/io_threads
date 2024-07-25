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

#include "io_threads/tcp_client.hpp" ///< for io_threads::tcp_client
#include "io_threads/tcp_client_thread.hpp" ///< for io_threads::tcp_client_thread
#include "io_threads/tls_client_context.hpp" ///< for io_threads::tls_client_context

#include <cstddef> ///< for size_t, std::byte
#include <memory> ///< for std::shared_ptr

namespace io_threads
{

struct tls_client_session;

class tls_client_context::tls_client : public tcp_client
{
private:
   using super = tcp_client;

public:
   tls_client() = delete;
   tls_client(tls_client &&) = delete;
   tls_client(tls_client const &) = delete;
   [[nodiscard]] tls_client(tcp_client_thread const &tcpClientThread, tls_client_context const &tlsClientContext);
   ~tls_client() override;

   tls_client &operator = (tls_client &&) = delete;
   tls_client &operator = (tls_client const &) = delete;

private:
   tls_client_session *m_session = nullptr;
   std::shared_ptr<tls_client_context::tls_client_context_impl> m_context;

   void io_connected() final;
   virtual void io_data_decrypted(std::byte const *bytes, size_t bytesLength) = 0;
   virtual size_t io_data_to_encrypt(std::byte *bytes, size_t bytesCapacity) = 0;
   size_t io_data_to_send(std::byte *bytes, size_t bytesCapacity) final;
   size_t io_data_to_shutdown(std::byte *bytes, size_t bytesCapacity) final;
   size_t io_data_received(std::byte const *bytes, size_t bytesLength) final;
   std::error_code io_last_error() const final;
};

using tls_client = tls_client_context::tls_client;

}
