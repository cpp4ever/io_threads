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

#include "tcp/rest/test_rest_server.hpp" ///< for io_threads::tests::test_rest_server
#include "tcp/test_tcp_common.hpp" ///< for EXPECT_ERROR_CODE
#include "tcp/test_tcp_server_context.hpp" ///< for io_threads::tests::test_tcp_server_context, io_threads::tests::test_tls_stream

#if (defined(_WIN32) || defined(_WIN64))
#  include <sdkddkver.h> ///< for _WIN32_WINNT
#endif
#include <boost/asio/ip/address.hpp> ///< for boost::asio::ip::address
#include <boost/asio/ip/tcp.hpp> ///< for boost::asio::ip::tcp::socket
#if (not defined(_WIN32) && not defined(_WIN64))
#  include <boost/asio/ssl/stream_base.hpp> ///< for boost::asio::ssl::stream_base::handshake_type
#endif
#include <boost/asio/strand.hpp> ///< for boost::asio::make_strand
#include <boost/beast.hpp> ///< for boost::beast::get_lowest_layer, boost::beast::tcp_stream
#include <boost/beast/http.hpp> ///< for boost::beast::http::async_read, boost::beast::http::async_write
#include <boost/system/error_code.hpp> ///< for boost::system::error_code
#if (defined(_WIN32) || defined(_WIN64))
#  include <boost/wintls/handshake_type.hpp> ///< for boost::wintls::handshake_type
#endif

#include <cstdint> ///< for uint16_t
#include <memory> ///< for std::make_unique
#include <thread> ///< for std::thread
#include <type_traits> ///< for std::is_same_v

namespace io_threads::tests
{

template<typename test_rest_stream>
test_rest_server<test_rest_stream>::test_rest_server(boost::asio::ip::address const &testAddress) :
   m_ioContext(1),
   m_acceptor(m_ioContext, {testAddress, 0}),
   m_buffer(1024),
   m_request(),
   m_response(),
   m_streams(),
   m_thread()
{
   m_thread = std::make_unique<std::thread>(
      &test_rest_server::thread_handler,
      this
   );
}

template<typename test_rest_stream>
test_rest_server<test_rest_stream>::~test_rest_server()
{
   m_ioContext.stop();
   m_thread->join();
}

template<typename test_rest_stream>
uint16_t test_rest_server<test_rest_stream>::local_port() const
{
   return m_acceptor.local_endpoint().port();
}

template<typename test_rest_stream>
void test_rest_server<test_rest_stream>::async_accept_socket()
{
   m_acceptor.async_accept(
      boost::asio::make_strand(m_ioContext),
      [this] (auto testErrorCode, auto testTcpSocket)
      {
         EXPECT_ERROR_CODE(testErrorCode);
         if ((false == testErrorCode.failed()) && (true == should_accept_socket()))
         {
            auto &stream = m_streams.emplace_back(test_tcp_server_context<test_rest_stream>::accept(std::move(testTcpSocket)));
            if constexpr (true == std::is_same_v<test_rest_stream, boost::beast::tcp_stream>)
            {
               if (true == should_pass_handshake())
               {
                  async_read(stream);
               }
               else
               {
                  boost::beast::get_lowest_layer(stream).close();
               }
            }
            else if constexpr (true == std::is_same_v<test_rest_stream, test_tls_stream>)
            {
               constexpr auto handshakeTimeout = std::chrono::milliseconds{100};
               boost::beast::get_lowest_layer(stream).expires_after(handshakeTimeout);
               stream.async_handshake(
#if (defined(_WIN32) || defined(_WIN64))
                  boost::wintls::handshake_type::server,
#else
                  boost::asio::ssl::stream_base::server,
#endif
                  [&] (auto testErrorCode)
                  {
                     EXPECT_ERROR_CODE(testErrorCode);
                     if ((false == testErrorCode.failed()) && (true == should_pass_handshake()))
                     {
                        async_read(stream);
                     }
                     else
                     {
                        boost::beast::get_lowest_layer(stream).close();
                     }
                  }
               );
            }
            else
            {
               assert(false && "must be unreachable!");
            }
         }
         else
         {
            testTcpSocket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, testErrorCode);
            EXPECT_ERROR_CODE(testErrorCode);
         }
         async_accept_socket();
      }
   );
}

template<typename test_rest_stream>
void test_rest_server<test_rest_stream>::async_read(test_rest_stream &stream)
{
   m_request = {};
   m_buffer.clear();
   constexpr auto readTimeout = std::chrono::milliseconds{100};
   boost::beast::get_lowest_layer(stream).expires_after(readTimeout);
   boost::beast::http::async_read(
      stream,
      m_buffer,
      m_request,
      [this, &stream] (auto testErrorCode, auto const)
      {
         if (
            false
            || (boost::beast::http::make_error_code(boost::beast::http::error::end_of_stream) == testErrorCode)
#if (defined(_WIN32) || defined(_WIN64))
            || (boost::wintls::error::make_error_code(SEC_I_CONTEXT_EXPIRED) == testErrorCode)
#else
            || false
#endif
         )
         {
            return;
         }
         EXPECT_ERROR_CODE(testErrorCode);
         if ((false == testErrorCode.failed()) && (true == handle_request(m_request, m_response)))
         {
            async_write(stream);
         }
         else
         {
            boost::beast::get_lowest_layer(stream).close();
         }
      }
   );
}

template<typename test_rest_stream>
void test_rest_server<test_rest_stream>::async_write(test_rest_stream &stream)
{
   constexpr auto writeTimeout = std::chrono::milliseconds{100};
   boost::beast::get_lowest_layer(stream).expires_after(writeTimeout);
   boost::beast::http::async_write(
      stream,
      m_response,
      [this, &stream] (auto testErrorCode, auto const)
      {
         EXPECT_ERROR_CODE(testErrorCode);
         if ((false == testErrorCode.failed()) && (true == should_keep_alive()))
         {
            async_read(stream);
         }
         else
         {
            boost::beast::get_lowest_layer(stream).close();
         }
      }
   );
}

template<typename test_rest_stream>
void test_rest_server<test_rest_stream>::thread_handler()
{
   async_accept_socket();
   m_ioContext.run();
}

template class test_rest_server<boost::beast::tcp_stream>;
template class test_rest_server<test_tls_stream>;

}
