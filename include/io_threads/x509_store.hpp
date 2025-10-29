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

#include <io_threads/network_interface.hpp> ///< for io_threads::network_interface
#include "io_threads/socket_address.hpp" ///< for io_threads::socket_address

#include <cstdint> ///< for uint8_t
#include <memory> ///< for std::shared_ptr
#include <optional> ///< for std::nullopt, std::optional
#include <string> ///< for std::string
#include <string_view> ///< for std::string_view
#include <vector> ///< for std::vector

namespace io_threads
{

struct domain_address
{
   std::string hostname;
   uint16_t port;
};

enum struct x509_format : uint8_t
{
   der [[maybe_unused]],
   pem [[maybe_unused]],
   p12 [[maybe_unused]],
};

class x509_store final
{
public:
   class tls_client_context;

   x509_store() = delete;
   [[nodiscard]] x509_store(x509_store &&rhs) noexcept;
   [[nodiscard]] x509_store(x509_store const &rhs) noexcept;
   [[nodiscard]] explicit x509_store(bool enableRevocationCheck);
   [[nodiscard]] x509_store(std::vector<domain_address> const &domainAddresses, bool enableRevocationCheck);
   [[nodiscard]] x509_store(std::string_view const &x509Data, x509_format const x509DataFormat);
   [[nodiscard]] x509_store(
      std::string_view const &x509Data,
      x509_format const x509DataFormat,
      std::string_view const &x509DataPassword
   );
   ~x509_store();

   x509_store &operator = (x509_store &&) = delete;
   x509_store &operator = (x509_store const &) = delete;

private:
   class x509_store_impl;
   std::shared_ptr<x509_store_impl> const m_impl;
};

}
