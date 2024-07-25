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

#include "io_threads/x509_store.hpp" ///< for io_threads::domain_address, io_threads::x509_format, io_threads::x509_store
#if (defined(IO_THREADS_OPENSSL))
#  include "openssl/x509_store_impl.hpp" ///< for io_threads::x509_store::x509_store_impl
#elif (defined(IO_THREADS_SCHANNEL))
#  include "windows/x509_store_impl.hpp" ///< for io_threads::x509_store::x509_store_impl
#endif

#include <memory> ///< for std::make_shared
#include <string_view> ///< for std::string_view
#include <vector> ///< for std::vector

namespace io_threads
{

x509_store::x509_store(x509_store &&rhs) noexcept = default;
x509_store::x509_store(x509_store const &rhs) noexcept = default;

x509_store::x509_store(bool const enableRevocationCheck) :
   m_impl{std::make_shared<x509_store_impl>(enableRevocationCheck),}
{}

x509_store::x509_store(std::vector<domain_address> const &domainAddresses, bool const enableRevocationCheck) :
   m_impl{std::make_shared<x509_store_impl>(domainAddresses, enableRevocationCheck),}
{}

x509_store::x509_store(std::string_view const &x509Data, x509_format const x509DataFormat) :
   m_impl{std::make_shared<x509_store_impl>(x509Data, x509DataFormat, std::string_view{"",}),}
{}

x509_store::x509_store(
   std::string_view const &x509Data,
   x509_format const x509DataFormat,
   std::string_view const &x509DataPassword
) :
   m_impl{std::make_shared<x509_store_impl>(x509Data, x509DataFormat, x509DataPassword),}
{}

x509_store::~x509_store() = default;

x509_store &x509_store::operator = (x509_store &&rhs) noexcept = default;
x509_store &x509_store::operator = (x509_store const &rhs) = default;

}
