/*
   Part of the io_threads project (https://github.com/cpp4ever/io_threads), under the MIT License
   SPDX-License-Identifier: MIT

   Copyright (c) 2024-2025 Mikhail Smirnov

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

#include "tcp/test_ssl_certificate.hpp"
#include "tcp/test_tcp_common.hpp"
#include "tcp/test_tcp_server_context.hpp"

namespace io_threads::tests
{

boost::beast::tcp_stream test_tcp_server_context<boost::beast::tcp_stream>::accept(boost::asio::ip::tcp::socket &&socket)
{
   return boost::beast::tcp_stream{std::move(socket)};
}

#if(defined(IO_THREADS_OPENSSL))
class [[nodiscard]] test_tls_context final
{
public:
   test_tls_context() :
      m_context(boost::asio::ssl::context::tls_server)
   {
      boost::system::error_code errorCode;
      m_context.set_options(boost::asio::ssl::context::default_workarounds, errorCode);
      EXPECT_ERROR_CODE(errorCode);
      m_context.use_certificate(
         boost::asio::buffer(test_certificate_pem()),
         boost::asio::ssl::context::pem,
         errorCode
      );
      EXPECT_ERROR_CODE(errorCode);
      m_context.use_private_key(
         boost::asio::buffer(test_private_key_rsa()),
         boost::asio::ssl::context::pem,
         errorCode
      );
      EXPECT_ERROR_CODE(errorCode);
   }

   test_tls_context(test_tls_context &&) = delete;
   test_tls_context(test_tls_context const &) = delete;

   test_tls_context &operator = (test_tls_context &&) = delete;
   test_tls_context &operator = (test_tls_context const &) = delete;

   boost::asio::ssl::context &ssl_context() noexcept
   {
      return m_context;
   }

private:
   boost::asio::ssl::context m_context;
};
#elif(defined(IO_THREADS_SCHANNEL))
class [[nodiscard]] test_tls_context final
{
public:
   test_tls_context() :
      m_context(wintls::method::system_default),
      m_privateKeyName("test-io-threads-certificate")
   {
      boost::system::error_code errorCode;
      wintls::delete_private_key(m_privateKeyName, errorCode);
      EXPECT_TRUE((false == bool{errorCode}) || (NTE_BAD_KEYSET == errorCode.value())) << errorCode.message();
      auto certificate = wintls::x509_to_cert_context(
         boost::asio::buffer(test_certificate_pem()),
         wintls::file_format::pem,
         errorCode
      );
      EXPECT_ERROR_CODE(errorCode);
      wintls::import_private_key(
         boost::asio::buffer(test_private_key_rsa()),
         wintls::file_format::pem,
         m_privateKeyName,
         errorCode
      );
      EXPECT_TRUE((false == bool{errorCode}) || (NTE_EXISTS == errorCode.value())) << errorCode.message();
      wintls::assign_private_key(certificate.get(), m_privateKeyName, errorCode);
      EXPECT_ERROR_CODE(errorCode);
      m_context.use_certificate(certificate.get(), errorCode);
      EXPECT_ERROR_CODE(errorCode);
   }

   test_tls_context(test_tls_context &&) = delete;
   test_tls_context(test_tls_context const &) = delete;

   ~test_tls_context()
   {
      boost::system::error_code errorCode;
      wintls::delete_private_key(m_privateKeyName, errorCode);
      EXPECT_ERROR_CODE(errorCode);
   }

   test_tls_context &operator = (test_tls_context &&) = delete;
   test_tls_context &operator = (test_tls_context const &) = delete;

   wintls::context &ssl_context() noexcept
   {
      return m_context;
   }

private:
   wintls::context m_context;
   std::string m_privateKeyName;
};
#endif

test_tls_stream test_tcp_server_context<test_tls_stream>::accept(boost::asio::ip::tcp::socket &&socket)
{
   static test_tls_context testContext{};
   return test_tls_stream{std::move(socket), testContext.ssl_context()};
}

boost::beast::websocket::stream<boost::beast::tcp_stream> test_tcp_server_context<boost::beast::websocket::stream<boost::beast::tcp_stream>>::accept(boost::asio::ip::tcp::socket &&socket)
{
   return boost::beast::websocket::stream<boost::beast::tcp_stream>{std::move(socket)};
}

boost::beast::websocket::stream<test_tls_stream> test_tcp_server_context<boost::beast::websocket::stream<test_tls_stream>>::accept(boost::asio::ip::tcp::socket &&socket)
{
   return boost::beast::websocket::stream<test_tls_stream>
   {
      test_tcp_server_context<test_tls_stream>::accept(std::move(socket)),
   };
}

}

#if (not defined(__clang__) && defined(__GNUC__) && defined(NDEBUG))
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
#include <boost/asio/impl/src.hpp>
#if(defined(IO_THREADS_OPENSSL))
#  include <boost/asio/ssl/impl/src.hpp>
#endif
#include <boost/beast/src.hpp>
#if (not defined(__clang__) && defined(__GNUC__) && defined(NDEBUG))
#  pragma GCC diagnostic pop
#endif
