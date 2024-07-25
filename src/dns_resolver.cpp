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

#include "io_threads/dns_resolver.hpp" ///< for io_threads::dns_resolver
#include "io_threads/socket_address.hpp" ///< for io_threads::socket_address
#if (defined(__linux__))
#  include "linux/dns_resolver_impl.hpp" ///< for AF_INET, AF_INET6, AF_UNSPEC, io_threads::resolve_domain_name
#elif (defined(_WIN32) || defined(_WIN64))
#  include "windows/dns_resolver_impl.hpp" ///< for AF_INET, AF_INET6, AF_UNSPEC, io_threads::resolve_domain_name
#endif

#include <cstdint> ///< for uint16_t
#include <string_view> ///< for std::string_view
#include <vector> ///< for std::vector

namespace io_threads
{

std::vector<socket_address> dns_resolver::resolve_all(std::string_view const &host, uint16_t const port)
{
   return resolve_domain_name(AF_UNSPEC, host, port);
}

std::vector<socket_address> dns_resolver::resolve_ipv4(std::string_view const &host, uint16_t const port)
{
   return resolve_domain_name(AF_INET, host, port);
}

std::vector<socket_address> dns_resolver::resolve_ipv6(std::string_view const &host, uint16_t const port)
{
   return resolve_domain_name(AF_INET6, host, port);
}

}
