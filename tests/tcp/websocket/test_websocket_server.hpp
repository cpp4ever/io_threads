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

template<typename test_websocket_stream>
class [[nodiscard]] test_websocket_server
{
public:
   test_websocket_server() = delete;
   test_websocket_server(test_websocket_server &&) = delete;
   test_websocket_server(test_websocket_server const &) = delete;
   [[nodiscard]] explicit test_websocket_server(boost::asio::ip::address const &testAddress);
   virtual ~test_websocket_server();

   test_websocket_server &operator = (test_websocket_server &&) = delete;
   test_websocket_server &operator = (test_websocket_server const &) = delete;

   [[nodiscard]] uint16_t local_port() const;

   MOCK_METHOD(bool, should_accept_socket, (), ());
   MOCK_METHOD(bool, should_pass_handshake, (), ());
   MOCK_METHOD(bool, should_accept_websocket, (), ());
   MOCK_METHOD(bool, handle_message, (boost::beast::flat_buffer const &inboundBuffer, std::string &outboundBuffer), ());
   MOCK_METHOD(bool, should_keep_alive, (), ());

private:
   boost::asio::io_context m_ioContext{1,};
   boost::asio::ip::tcp::acceptor m_acceptor;
   struct test_websocket_client final
   {
      test_websocket_stream stream;
      boost::beast::flat_buffer inboundBuffer{1024,};
      std::string outboundBuffer{};
   };
   std::deque<test_websocket_client> m_clients{};
   std::thread m_thread;

   void async_read(test_websocket_client &stream);
   void async_socket_accept();
   void async_websocket_accept(test_websocket_client &stream);
   void async_write(test_websocket_client &stream);

   void thread_handler();
};

}
