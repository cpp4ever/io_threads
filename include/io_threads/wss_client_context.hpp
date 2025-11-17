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

#include "io_threads/tls_client_context.hpp" ///< for io_threads::tls_client_context
#include "io_threads/tcp_client_thread.hpp" ///< for io_threads::tcp_client_thread

#include <cstdint> ///< for uint32_t
#include <memory> ///< for std::shared_ptr

namespace io_threads
{

class wss_client_context final
{
public:
   class wss_client;

   wss_client_context() = delete;
   [[nodiscard]] wss_client_context(wss_client_context &&rhs) noexcept;
   [[nodiscard]] wss_client_context(wss_client_context const &rhs) noexcept;
   [[nodiscard]] wss_client_context(tls_client_context tlsClientContext, uint32_t sessionListCapacity, uint32_t inboundBufferSize, uint32_t outboundBufferSize);
   ~wss_client_context();

   wss_client_context &operator = (wss_client_context &&) = delete;
   wss_client_context &operator = (wss_client_context const &) = delete;

   [[maybe_unused, nodiscard]] tcp_client_thread const &executor() const noexcept
   {
      return m_tlsClientContext.executor();
   }

private:
   tls_client_context const m_tlsClientContext;
   class wss_client_context_impl;
   std::shared_ptr<wss_client_context_impl> m_impl{nullptr,};
};

}
