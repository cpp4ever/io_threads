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

#if (defined(_WIN32) || defined(_WIN64))
#  include <sdkddkver.h> ///< for _WIN32_WINNT
#endif
#if (not defined(__clang__) && defined(__GNUC__) && defined(NDEBUG))
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
#if (defined(IO_THREADS_OPENSSL))
#  include <boost/asio/ssl/stream.hpp>
#endif
#include <boost/beast.hpp>
#if (not defined(__clang__) && defined(__GNUC__) && defined(NDEBUG))
#  pragma GCC diagnostic pop
#endif
#if (defined(IO_THREADS_SCHANNEL))
#  include <wintls.hpp>
#endif

namespace io_threads::tests
{

template<typename tcp_stream>
struct test_tcp_server_context;

template<>
struct [[nodiscard]] test_tcp_server_context<boost::beast::tcp_stream>
{
   [[nodiscard]] static boost::beast::tcp_stream accept(boost::asio::ip::tcp::socket &&socket);
};

#if(defined(IO_THREADS_OPENSSL))
using test_tls_stream = boost::asio::ssl::stream<boost::beast::tcp_stream>;
#elif(defined(IO_THREADS_SCHANNEL))
using test_tls_stream = wintls::stream<boost::beast::tcp_stream>;
#endif

template<>
struct [[nodiscard]] test_tcp_server_context<test_tls_stream>
{
   [[nodiscard]] static test_tls_stream accept(boost::asio::ip::tcp::socket &&socket);
};

template<>
struct [[nodiscard]] test_tcp_server_context<boost::beast::websocket::stream<boost::beast::tcp_stream>>
{
   [[nodiscard]] static boost::beast::websocket::stream<boost::beast::tcp_stream> accept(boost::asio::ip::tcp::socket &&socket);
};

template<>
struct [[nodiscard]] test_tcp_server_context<boost::beast::websocket::stream<test_tls_stream>>
{
   [[nodiscard]] static boost::beast::websocket::stream<test_tls_stream> accept(boost::asio::ip::tcp::socket &&socket);
};

}
