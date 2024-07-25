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

#include "tcp/rest/test_rest_server.hpp"
#include "tcp/test_tcp_common.hpp"
#include "tcp/test_tcp_server_context.hpp"

#if (not defined(__clang__) && defined(__GNUC__) && defined(NDEBUG))
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
#include <boost/asio/strand.hpp>
#if (not defined(__clang__) && defined(__GNUC__) && defined(NDEBUG))
#  pragma GCC diagnostic pop
#endif

namespace io_threads::tests
{

template<typename test_rest_stream>
test_rest_server<test_rest_stream>::test_rest_server(boost::asio::ip::address const &testAddress) :
   m_ioContext{1,},
   m_acceptor{m_ioContext, {testAddress, 0,},},
   m_buffer{1024,},
   m_request{},
   m_response{},
   m_streams{},
   m_thread{}
{
   m_thread = std::thread{[this] () { thread_handler(); },};
}

template<typename test_rest_stream>
test_rest_server<test_rest_stream>::~test_rest_server()
{
   m_ioContext.stop();
   m_thread.join();
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
      [this] (auto errorCode, auto tcpSocket)
      {
         EXPECT_ERROR_CODE(errorCode);
         if ((false == bool{errorCode,}) && (true == should_accept_socket()))
         {
            auto &stream{m_streams.emplace_back(test_tcp_server_context<test_rest_stream>::accept(std::move(tcpSocket))),};
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
               constexpr auto handshakeTimeout{std::chrono::seconds{1,},};
               boost::beast::get_lowest_layer(stream).expires_after(handshakeTimeout);
               stream.async_handshake(
#if(defined(IO_THREADS_OPENSSL))
                  boost::asio::ssl::stream_base::server,
#elif(defined(IO_THREADS_SCHANNEL))
                  wintls::handshake_type::server,
#endif
                  [this, &stream] (auto const errorCode)
                  {
                     EXPECT_ERROR_CODE(errorCode);
                     if ((false == bool{errorCode,}) && (true == should_pass_handshake()))
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
            tcpSocket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, errorCode);
            EXPECT_ERROR_CODE(errorCode);
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
   constexpr auto readTimeout{std::chrono::seconds{1,},};
   boost::beast::get_lowest_layer(stream).expires_after(readTimeout);
   boost::beast::http::async_read(
      stream,
      m_buffer,
      m_request,
      [this, &stream] (auto const errorCode, auto const)
      {
         if (
            false
            || (boost::beast::http::make_error_code(boost::beast::http::error::end_of_stream) == errorCode)
#if(defined(IO_THREADS_OPENSSL))
            || false
#elif(defined(IO_THREADS_SCHANNEL))
            || (wintls::error::make_error_code(SEC_I_CONTEXT_EXPIRED) == errorCode)
#endif
         )
         {
            return;
         }
         EXPECT_ERROR_CODE(errorCode);
         if ((false == bool{errorCode,}) && (true == handle_request(m_request, m_response)))
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
   constexpr auto writeTimeout = std::chrono::seconds{1,};
   boost::beast::get_lowest_layer(stream).expires_after(writeTimeout);
   m_responseSerializer = std::make_unique<boost::beast::http::serializer<false, boost::beast::http::string_body>>(m_response);
   boost::beast::http::async_write(
      stream,
      *m_responseSerializer,
      [this, &stream] (auto const errorCode, auto const)
      {
         EXPECT_ERROR_CODE(errorCode);
         if (true == m_responseSerializer->is_done())
         {
            m_responseSerializer.reset();
            if ((false == bool{errorCode,}) && (true == should_keep_alive()))
            {
               async_read(stream);
            }
            else
            {
               boost::beast::get_lowest_layer(stream).close();
            }
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
