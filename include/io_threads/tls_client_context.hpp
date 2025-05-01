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

#include "io_threads/tcp_client_thread.hpp" ///< for io_threads::tcp_client_thread
#include "io_threads/x509_store.hpp" ///< for io_threads::x509_store

#include <cstddef> ///< for size_t
#include <memory> ///< for std::shared_ptr
#include <string_view> ///< for std::string_view

namespace io_threads
{

class x509_store::tls_client_context final
{
public:
   class tls_client;

   tls_client_context() = delete;
   [[nodiscard]] tls_client_context(tls_client_context &&rhs) noexcept;
   [[nodiscard]] tls_client_context(tls_client_context const &rhs) noexcept;
   [[nodiscard]] tls_client_context(
      tcp_client_thread const &executor,
      x509_store const &x509Store,
      std::string_view const &domainName,
      size_t tlsSessionListCapacity
   );
   ~tls_client_context();

   tls_client_context &operator = (tls_client_context &&rhs) noexcept;
   tls_client_context &operator = (tls_client_context const &rhs);

   [[maybe_unused, nodiscard]] tcp_client_thread const &executor() const noexcept
   {
      return m_executor;
   }

private:
   class tls_client_context_impl;

   tcp_client_thread m_executor;
   std::shared_ptr<tls_client_context_impl> m_impl{nullptr};
};

using tls_client_context [[maybe_unused]] = x509_store::tls_client_context;

}
