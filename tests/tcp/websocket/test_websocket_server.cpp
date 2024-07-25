/*
   Part of the webThread Project (https://github.com/cpp4ever/webthread), under the MIT License
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

#include "tcp/test_tcp_common.hpp"
#include "tcp/test_tcp_server_context.hpp"
#include "tcp/websocket/test_websocket_server.hpp"

#if (not defined(__clang__) && defined(__GNUC__) && defined(NDEBUG))
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
#include <boost/asio/strand.hpp>
#if(defined(IO_THREADS_OPENSSL))
#  include <boost/asio/ssl/error.hpp>
#  include <boost/beast/websocket/ssl.hpp>
#endif
#if (not defined(__clang__) && defined(__GNUC__) && defined(NDEBUG))
#  pragma GCC diagnostic pop
#endif

#if (defined(_WIN32) || defined(_WIN64))
namespace boost::beast
{

template<typename TeardownHandler>
void async_teardown(role_type const, io_threads::tests::test_tls_stream &stream, TeardownHandler &&handler)
{
   stream.async_shutdown(std::forward<TeardownHandler>(handler));
}

}
#endif

namespace io_threads::tests
{

template<typename test_websocket_stream>
test_websocket_server<test_websocket_stream>::test_websocket_server(boost::asio::ip::address const &testAddress) :
   m_ioContext(1),
   m_acceptor(m_ioContext, {testAddress, 0}),
   m_inboundBuffer(1024),
   m_outboundBuffer(),
   m_streams(),
   m_thread()
{
   m_thread = std::thread{&test_websocket_server::thread_handler, this,};
}

template<typename test_websocket_stream>
test_websocket_server<test_websocket_stream>::~test_websocket_server()
{
   m_ioContext.stop();
   m_thread.join();
}

template<typename test_websocket_stream>
uint16_t test_websocket_server<test_websocket_stream>::local_port() const
{
   return m_acceptor.local_endpoint().port();
}

template<typename test_websocket_stream>
void test_websocket_server<test_websocket_stream>::async_read(test_websocket_stream &stream)
{
   m_inboundBuffer.clear();
   stream.async_read(
      m_inboundBuffer,
      [&] (auto testErrorCode, auto const)
      {
         if (
            false
#if(defined(IO_THREADS_OPENSSL))
            || (boost::asio::ssl::error::make_error_code(boost::asio::ssl::error::stream_errors::stream_truncated) == testErrorCode)
#  if (defined(_WIN32) || defined(_WIN64))
            || (std::error_code{WSAECONNABORTED, std::system_category(),} == testErrorCode)
#  endif
#endif
            || (boost::beast::websocket::make_error_code(boost::beast::websocket::error::closed) == testErrorCode)
            || (boost::asio::error::make_error_code(boost::asio::error::eof) == testErrorCode)
         )
         {
            return;
         }
         EXPECT_ERROR_CODE(testErrorCode);
         m_outboundBuffer.clear();
         if ((false == testErrorCode.failed()) && (true == handle_message(m_inboundBuffer, m_outboundBuffer)))
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

template<typename test_websocket_stream>
void test_websocket_server<test_websocket_stream>::async_socket_accept()
{
   m_acceptor.async_accept(
      boost::asio::make_strand(m_ioContext),
      [&] (auto testErrorCode, auto testTcpSocket)
      {
         EXPECT_ERROR_CODE(testErrorCode);
         if ((false == testErrorCode.failed()) && (true == should_accept_socket()))
         {
            auto &stream = m_streams.emplace_back(test_tcp_server_context<test_websocket_stream>::accept(std::move(testTcpSocket)));
            if constexpr (std::is_same_v<test_websocket_stream, boost::beast::websocket::stream<boost::beast::tcp_stream>>)
            {
               if (true == should_pass_handshake())
               {
                  async_websocket_accept(stream);
               }
               else
               {
                  boost::beast::get_lowest_layer(stream).close();
               }
            }
            else if constexpr (std::is_same_v<test_websocket_stream, boost::beast::websocket::stream<test_tls_stream>>)
            {
               constexpr auto handshakeTimeout = std::chrono::milliseconds{100};
               boost::beast::get_lowest_layer(stream).expires_after(handshakeTimeout);
               stream.next_layer().async_handshake(
#if(defined(IO_THREADS_OPENSSL))
                  boost::asio::ssl::stream_base::server,
#elif(defined(IO_THREADS_SCHANNEL))
                  wintls::handshake_type::server,
#endif
                  [&] (auto testErrorCode)
                  {
                     EXPECT_ERROR_CODE(testErrorCode);
                     if ((false == testErrorCode.failed()) && (true == should_pass_handshake()))
                     {
                        async_websocket_accept(stream);
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
            testTcpSocket.close(testErrorCode);
            EXPECT_ERROR_CODE(testErrorCode);
         }
         async_socket_accept();
      }
   );
}

template<typename test_websocket_stream>
void test_websocket_server<test_websocket_stream>::async_websocket_accept(test_websocket_stream &stream)
{
   boost::beast::get_lowest_layer(stream).expires_never();
   stream.set_option(
      boost::beast::websocket::permessage_deflate
      {
         .server_enable = true,
         .client_enable = true,
         .server_no_context_takeover = true,
         .client_no_context_takeover = true,
      }
   );
   stream.set_option(
      boost::beast::websocket::stream_base::timeout::suggested(
         boost::beast::role_type::server
      )
   );
   stream.async_accept(
      [&] (auto testErrorCode)
      {
         if (boost::beast::websocket::error::closed == testErrorCode)
         {
            return;
         }
         EXPECT_ERROR_CODE(testErrorCode);
         if ((false == testErrorCode.failed()) && (true == should_accept_websocket()))
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

template<typename test_websocket_stream>
void test_websocket_server<test_websocket_stream>::async_write(test_websocket_stream &stream)
{
   stream.text(stream.got_text());
   stream.async_write(
      boost::asio::buffer(static_cast<std::string const &>(m_outboundBuffer)),
      [&] (auto testErrorCode, auto const)
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

template<typename test_websocket_stream>
void test_websocket_server<test_websocket_stream>::thread_handler()
{
   async_socket_accept();
   m_ioContext.run();
}

template class test_websocket_server<boost::beast::websocket::stream<boost::beast::tcp_stream, true>>;
template class test_websocket_server<boost::beast::websocket::stream<test_tls_stream, true>>;

}
