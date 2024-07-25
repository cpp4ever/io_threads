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

#include "io_threads/ssl_certificate.hpp" ///< for io_threads::ssl_certificate

#include <memory> ///< for std::shared_ptr
#include <string_view> ///< for std::string_view

namespace io_threads
{

class tls_client_context final
{
public:
   class tls_client;

   tls_client_context() = delete;
   [[nodiscard]] tls_client_context(tls_client_context &&rhs) noexcept;
   [[nodiscard]] tls_client_context(tls_client_context const &rhs) noexcept;
   [[nodiscard]] tls_client_context(std::string_view domainName, size_t initialTlsClientSessionListCapacity);
   [[nodiscard]] tls_client_context(
      std::string_view domainName,
      ssl_certificate const &sslCertificate,
      size_t initialTlsClientSessionListCapacity
   );
   ~tls_client_context();

   tls_client_context &operator = (tls_client_context &&rhs) noexcept;
   tls_client_context &operator = (tls_client_context const &rhs);

private:
   class tls_client_context_impl;

   std::shared_ptr<tls_client_context_impl> m_impl;
};

}
