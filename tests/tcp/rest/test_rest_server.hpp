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
#include <boost/beast.hpp>
#if (not defined(__clang__) && defined(__GNUC__) && defined(NDEBUG))
#  pragma GCC diagnostic pop
#endif
#include <gmock/gmock.h>

#include <deque>
#include <thread>

namespace io_threads::tests
{

template<typename test_rest_stream>
class [[nodiscard]] test_rest_server
{
public:
   test_rest_server() = delete;
   test_rest_server(test_rest_server &&) = delete;
   test_rest_server(test_rest_server const &) = delete;
   [[nodiscard]] explicit test_rest_server(boost::asio::ip::address const &testAddress);
   virtual ~test_rest_server();

   test_rest_server &operator = (test_rest_server &&) = delete;
   test_rest_server &operator = (test_rest_server const &) = delete;

   [[nodiscard]] uint16_t local_port() const;

   MOCK_METHOD(bool, should_accept_socket, (), ());
   MOCK_METHOD(bool, should_pass_handshake, (), ());
   MOCK_METHOD(
      bool,
      handle_request,
      (
         boost::beast::http::request<boost::beast::http::string_body> const &request,
         boost::beast::http::response<boost::beast::http::string_body> &response
      ),
      ()
   );
   MOCK_METHOD(bool, should_keep_alive, (), ());

private:
   boost::asio::io_context m_ioContext;
   boost::asio::ip::tcp::acceptor m_acceptor;
   boost::beast::flat_buffer m_buffer;
   boost::beast::http::request<boost::beast::http::string_body> m_request;
   boost::beast::http::response<boost::beast::http::string_body> m_response;
   std::unique_ptr<boost::beast::http::serializer<false, boost::beast::http::string_body>> m_responseSerializer{nullptr,};
   std::deque<test_rest_stream> m_streams;
   std::thread m_thread;

   void async_accept_socket();
   void async_read(test_rest_stream &stream);
   void async_write(test_rest_stream &stream);

   void thread_handler();
};

#define EXPECT_HTTP_REQUEST(testRequest, testMethod, testTarget, testHeaders, testBody)   \
{                                                                                         \
   EXPECT_EQ((testRequest).version(), 11U);                                               \
   EXPECT_EQ((testRequest).method(), (testMethod));                                       \
   EXPECT_EQ(std::string_view{(testRequest).target()}, (testTarget));                     \
   for (auto const &testHeader : (testRequest))                                           \
   {                                                                                      \
      EXPECT_EQ(testHeader.value(), (testHeaders)[testHeader.name_string()])              \
         << std::string_view{testHeader.name_string()};                                   \
   }                                                                                      \
   for (auto const [testHeaderName, testHeaderValue] : (testHeaders))                     \
   {                                                                                      \
      EXPECT_EQ((testRequest)[testHeaderName], testHeaderValue)                           \
         << testHeaderName;                                                               \
   }                                                                                      \
   EXPECT_EQ(std::string_view{(testRequest).body()}, std::string_view{(testBody)});       \
}

}
