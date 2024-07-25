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

#include "tcp/test_tcp_certificate.hpp" ///< for test_certificate_pem, test_private_key_rsa
#include "tcp/test_tcp_common.hpp" ///< for EXPECT_ERROR_CODE
#include "tcp/test_tcp_server_context.hpp" ///< for test_tcp_server_context

#if (defined(_WIN32) || defined(_WIN64))
#  include <sdkddkver.h> ///< for _WIN32_WINNT
#endif
#include <boost/asio/buffer.hpp> ///< for boost::asio::buffer
#include <boost/asio/ip/tcp.hpp> ///< for boost::asio::ip::tcp::socket
#if (not defined(_WIN32) && not defined(_WIN64))
#  include <boost/asio/ssl/context.hpp> ///< for boost::asio::ssl::context
#endif
#include <boost/beast.hpp> ///< for boost::beast::tcp_stream
#include <boost/system/error_code.hpp> ///< for boost::system::error_code
#if (defined(_WIN32) || defined(_WIN64))
#  include <boost/wintls/certificate.hpp> ///< for boost::wintls::assign_private_key, boost::wintls::delete_private_key, boost::wintls::import_private_key, boost::wintls::x509_to_cert_context
#  include <boost/wintls/context.hpp> ///< for boost::wintls::context
#  include <boost/wintls/file_format.hpp> ///< for boost::wintls::file_format
#  include <boost/wintls/method.hpp> ///< for boost::wintls::method
#endif
#include <gtest/gtest.h> ///< for EXPECT_TRUE
#if (defined(_WIN32) || defined(_WIN64))
#  include <winerror.h> ///< for NTE_EXISTS, NTE_BAD_KEYSET
#endif

#if (defined(_WIN32) || defined(_WIN64))
#  include <string> ///< for std::string
#endif

namespace io_threads::tests
{

boost::beast::tcp_stream test_tcp_server_context<boost::beast::tcp_stream>::accept(boost::asio::ip::tcp::socket &&socket)
{
   return boost::beast::tcp_stream{std::move(socket)};
}

#if (defined(WIN32))
class [[nodiscard]] test_tls_context final
{
public:
   test_tls_context() :
      m_context(boost::wintls::method::system_default),
      m_privateKeyName("test-io-threads-certificate")
   {
      boost::system::error_code errorCode;
      boost::wintls::delete_private_key(m_privateKeyName, errorCode);
      EXPECT_TRUE((false == errorCode.failed()) || (NTE_BAD_KEYSET == errorCode.value())) << errorCode.message();
      auto certificate = boost::wintls::x509_to_cert_context(
         boost::asio::buffer(test_certificate_pem()),
         boost::wintls::file_format::pem,
         errorCode
      );
      EXPECT_ERROR_CODE(errorCode);
      boost::wintls::import_private_key(
         boost::asio::buffer(test_private_key_rsa()),
         boost::wintls::file_format::pem,
         m_privateKeyName,
         errorCode
      );
      EXPECT_TRUE((false == errorCode.failed()) || (NTE_EXISTS == errorCode.value())) << errorCode.message();
      boost::wintls::assign_private_key(certificate.get(), m_privateKeyName, errorCode);
      EXPECT_ERROR_CODE(errorCode);
      m_context.use_certificate(certificate.get(), errorCode);
      EXPECT_ERROR_CODE(errorCode);
   }

   test_tls_context(test_tls_context &&) = delete;
   test_tls_context(test_tls_context const &) = delete;

   ~test_tls_context()
   {
      boost::system::error_code errorCode;
      boost::wintls::delete_private_key(m_privateKeyName, errorCode);
      EXPECT_ERROR_CODE(errorCode);
   }

   test_tls_context &operator = (test_tls_context &&) = delete;
   test_tls_context &operator = (test_tls_context const &) = delete;

   boost::wintls::context &ssl_context() noexcept
   {
      return m_context;
   }

private:
   boost::wintls::context m_context;
   std::string m_privateKeyName;
};
#else
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
