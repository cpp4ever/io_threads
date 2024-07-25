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

#include "io_threads/ssl_certificate_type.hpp" ///< for io_threads::ssl_certificate_type

#include <string_view> ///< for std::string_view

namespace io_threads
{

class ssl_certificate final
{
public:
   ssl_certificate() = delete;
   [[maybe_unused, nodiscard]] constexpr ssl_certificate(ssl_certificate &&rhs) noexcept = default;
   [[maybe_unused, nodiscard]] constexpr ssl_certificate(ssl_certificate const &rhs) noexcept = default;

   [[maybe_unused, nodiscard]] constexpr ssl_certificate(
      std::string_view const sslCertificate,
      ssl_certificate_type const sslCertificateType
   ) noexcept :
      m_content{sslCertificate},
      m_type{sslCertificateType}
   {}

   [[maybe_unused]] constexpr ssl_certificate &operator = (ssl_certificate &&rhs) noexcept = default;
   [[maybe_unused]] constexpr ssl_certificate &operator = (ssl_certificate const &rhs) noexcept = default;

   [[maybe_unused, nodiscard]] constexpr std::string_view content() const noexcept
   {
      return m_content;
   }

   [[maybe_unused, nodiscard]] constexpr std::string_view password() const noexcept
   {
      return m_password;
   }

   [[maybe_unused, nodiscard]] constexpr ssl_certificate_type type() const noexcept
   {
      return m_type;
   }

   [[maybe_unused, nodiscard]] constexpr ssl_certificate with_password(std::string_view const password) const noexcept
   {
      auto value{*this};
      value.m_password = password;
      return value;
   }

private:
   std::string_view m_content;
   std::string_view m_password{};
   ssl_certificate_type m_type;
};

}
