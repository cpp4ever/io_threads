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

#include "tcp/rest/test_rest_server.hpp" ///< for EXPECT_HTTP_REQUEST, test_rest_server
#include "tcp/test_tcp_common.hpp" ///< for test_bad_request_timeout, test_good_request_timeout, test_loopback_ip, test_non_routable_ips

#include <io_threads/system_network_interfaces.hpp> ///< for io_threads::system_network_interfaces
#include <io_threads/tcp_client.hpp> ///< for io_threads::tcp_client
#include <io_threads/tcp_client_config.hpp> ///< for io_threads::tcp_client_config
#include <io_threads/tcp_client_thread.hpp> ///< for io_threads::tcp_client_thread

#if (defined(_WIN32) || defined(_WIN64))
#  include <sdkddkver.h> ///< for _WIN32_WINNT
#endif
#include <boost/asio/ip/address.hpp> ///< for boost::asio::ip::make_address
#include <boost/beast/http/field.hpp> ///< for boost::beast::http::field
#include <boost/beast/http/status.hpp> /// boost::beast::http::status
#include <boost/beast/http/verb.hpp> ///< for boost::beast::http::verb
#include <gmock/gmock.h> ///< for EXPECT_CALL, EXPECT_THAT, testing::AnyOf, testing::Return, testing::StrictMock, testing::_
#include <gtest/gtest.h> ///< for EXPECT_TRUE

#include <cstddef> ///< for size_t
#include <format> ///< for std::format
#include <future> ///< for std::future_status, std::promise
#include <map> ///< for std::map
#include <memory> ///< for std::make_shared
#include <string> ///< for std::string, std::to_string
#include <string_view> ///< for std::string_view

namespace io_threads::tests
{

class tcp_client_mock : public tcp_client
{
public:
   using tcp_client::tcp_client;

   tcp_client_mock &operator = (tcp_client_mock &&) = delete;
   tcp_client_mock &operator = (tcp_client_mock const &) = delete;

   void expect_disconnect()
   {
      EXPECT_CALL(*this, io_disconnected(testing::_))
         .WillOnce(
            [this] (auto const errorCode)
            {
               EXPECT_FALSE(errorCode) << errorCode.value() << ": " << errorCode.message();
               m_done.set_value();
            }
         )
      ;
      ready_to_disconnect();
   }

   void expect_error(std::error_code const expectedErrorCode)
   {
      EXPECT_CALL(*this, io_disconnected(testing::_))
         .WillOnce(
            [this, expectedErrorCode] (auto const errorCode)
            {
               EXPECT_EQ(expectedErrorCode, errorCode) << errorCode.value() << ": " << errorCode.message();
               m_done.set_value();
            }
         )
      ;
   }

   void expect_error_on_send(std::string const &message, std::error_code const expectedErrorCode)
   {
      EXPECT_CALL(*this, io_ready_to_send(testing::_))
         .WillOnce(
            [this, message, expectedErrorCode] (auto dataChunk)
            {
               expect_error(expectedErrorCode);
               return data_chunk{.data = message.data(), .size = message.size()};
            }
         )
      ;
      if (true == m_asleep.exchange(false, std::memory_order_acq_rel))
      {
         ready_to_send();
      }
   }

   void expect_ready_to_connect(tcp_client_config const &testConfig)
   {
      EXPECT_CALL(*this, io_ready_to_connect()).WillOnce(testing::Return(testConfig));
      ready_to_connect();
   }

   void expect_ready_to_send(std::string const &message)
   {
      EXPECT_CALL(*this, io_ready_to_send(testing::_))
         .WillOnce(
            [this, message] (auto)
            {
               EXPECT_CALL(*this, io_ready_to_send(testing::_)).WillOnce(
                  [this] (auto)
                  {
                     m_asleep.store(true, std::memory_order_release);
                     return data_chunk{};
                  }
               );
               return data_chunk{.data = message.data(), .size = message.size()};
            }
         )
      ;
      if (true == m_asleep.exchange(false, std::memory_order_acq_rel))
      {
         ready_to_send();
      }
   }

   template<typename recv_handler>
   void expect_recv(std::string const &message, recv_handler &&recvHandler)
   {
      m_recvdMessage.clear();
      m_recvdMessage.reserve(message.size() + 1);
      expect_recv_recursive(
         [this, message, recvHandler] (auto const dataChunk)
         {
            m_recvdMessage += std::string_view{std::bit_cast<char const *>(dataChunk.data), dataChunk.size};
            if (m_recvdMessage.size() < message.size())
            {
               return false;
            }
            EXPECT_EQ(m_recvdMessage, message) << m_recvdMessage;
            recvHandler();
            return true;
         }
      );
   }

   auto wait_for(std::chrono::seconds const timeout) const
   {
      return m_doneFuture.wait_for(timeout);
   }

private:
   std::string m_recvdMessage = {};
   std::atomic_bool m_asleep = false;
   std::promise<void> m_done = {};
   std::future<void> m_doneFuture = m_done.get_future();

   MOCK_METHOD(void, io_disconnected, (std::error_code errorCode), (final));
   MOCK_METHOD(tcp_client_config, io_ready_to_connect, (), (final));
   MOCK_METHOD(data_chunk, io_ready_to_send, (data_chunk dataChunk), (final));
   MOCK_METHOD(void, io_recv, (data_chunk dataChunk), (final));


   template<typename recv_handler>
   void expect_recv_recursive(recv_handler &&recvHandler)
   {
      EXPECT_CALL(*this, io_recv(testing::_))
         .WillOnce(
            [this, recvHandler] (auto const dataChunk)
            {
               if (false == recvHandler(dataChunk))
               {
                  expect_recv_recursive(std::move(recvHandler));
               }
            }
         )
      ;
   }
};

using test_tcp_client = testing::StrictMock<tcp_client_mock>;

template<typename test_rest_stream>
void test_rest_client()
{
   constexpr size_t testConnectionsCapacity = 0;
   constexpr size_t testRecvBufferSize = 25;
   constexpr size_t testSendBufferSize = 25;
#if (defined(_WIN32) || defined(_WIN64))
   auto const connect_timeout_error_code = std::error_code{WSAETIMEDOUT, std::system_category()};
   auto const connection_reset_error_code = std::error_code{WSAECONNRESET, std::system_category()};
#else
   auto const connect_timeout_error_code = std::error_code{};
   auto const connection_reset_error_code = std::error_code{};
#endif
   auto const testThread = tcp_client_thread{test_cpu_id, testConnectionsCapacity, testRecvBufferSize, testSendBufferSize};
   /// Connect timeout
   for (auto const &testNonRoutableIp : test_non_routable_ips)
   {
      test_tcp_client testClient{testThread};
      std::error_code testErrorCode = {};
      auto const testSocketAddress = make_socket_address(testNonRoutableIp, test_peer_port, testErrorCode);
      ASSERT_FALSE(testErrorCode) << testErrorCode.value() << ": " << testErrorCode.message();
      ASSERT_TRUE(testSocketAddress.has_value());
      testClient.expect_error(connect_timeout_error_code);
      testClient.expect_ready_to_connect(tcp_client_config{tcp_client_address{testSocketAddress.value()}}.with_user_timeout(test_bad_request_timeout));
      EXPECT_EQ(std::future_status::ready, testClient.wait_for(test_good_request_timeout * 2)) << testNonRoutableIp;
   }
   system_network_interfaces testNetworkInterfaces{};
   auto const testLoopbackNetworkInterface = testNetworkInterfaces.loopback();
   ASSERT_TRUE(testLoopbackNetworkInterface.has_value());
   ASSERT_TRUE(testLoopbackNetworkInterface.value().ip_v4().has_value());
   auto const testPeerHost = std::string_view{testLoopbackNetworkInterface->ip_v4().value()};
   ASSERT_FALSE(testPeerHost.empty());
   testing::StrictMock<test_rest_server<test_rest_stream>> testRestServer{boost::asio::ip::make_address(testPeerHost)};
   std::error_code testErrorCode = {};
   auto const testSocketAddress = make_socket_address(testPeerHost, testRestServer.local_port(), testErrorCode);
   ASSERT_FALSE(testErrorCode) << testErrorCode.value() << ": " << testErrorCode.message();
   ASSERT_TRUE(testSocketAddress.has_value());
   auto const testConfig =
      tcp_client_config{tcp_client_address{testLoopbackNetworkInterface.value(), testSocketAddress.value()}}
      .with_keep_alive(tcp_keep_alive{.idleTimeout = std::chrono::seconds{1}, .probeTimeout = std::chrono::seconds{1}, .probesCount = 1})
      .with_nodelay()
      .with_user_timeout(test_good_request_timeout)
   ;
   auto const testContentType = std::string{"application/json"};
   /// Disconnect on socket accept
   {
      EXPECT_CALL(testRestServer, should_accept_socket()).WillOnce(testing::Return(false));
      test_tcp_client testClient{testThread};
      auto const testHttpRequest = std::format("GET / HTTP/1.1\r\nHost:{}\r\nAccept:*/*\r\n\r\n", testPeerHost);
      testClient.expect_error_on_send(testHttpRequest, connection_reset_error_code);
      testClient.expect_ready_to_connect(testConfig);
      EXPECT_EQ(std::future_status::ready, testClient.wait_for(test_good_request_timeout));
   }
   /// Disconnect on handshake
   {
      EXPECT_CALL(testRestServer, should_accept_socket()).WillOnce(testing::Return(true));
      EXPECT_CALL(testRestServer, should_pass_handshake()).WillOnce(testing::Return(false));
      test_tcp_client testClient{testThread};
      auto const testHttpRequest = std::format("GET / HTTP/1.1\r\nHost:{}\r\nAccept:*/*\r\n\r\n", testPeerHost);
      testClient.expect_ready_to_send(testHttpRequest);
      testClient.expect_error(connection_reset_error_code);
      testClient.expect_ready_to_connect(testConfig);
      EXPECT_EQ(std::future_status::ready, testClient.wait_for(test_good_request_timeout));
   }
   /// Disconnect on request
   {
      EXPECT_CALL(testRestServer, should_accept_socket()).WillOnce(testing::Return(true));
      EXPECT_CALL(testRestServer, should_pass_handshake()).WillOnce(testing::Return(true));
      EXPECT_CALL(testRestServer, handle_request(testing::_, testing::_))
         .WillOnce(
            [&] (auto const &testRequest, auto &)
            {
               auto testHeaders = std::map<std::string_view, std::string_view>
               {
                  {"Accept", "*/*"},
                  {"Host", testPeerHost},
               };
               EXPECT_HTTP_REQUEST(testRequest, boost::beast::http::verb::get, "/", testHeaders, "");
               return false;
            }
         )
      ;
      test_tcp_client testClient{testThread};
      auto const testHttpRequest = std::format("GET / HTTP/1.1\r\nHost:{}\r\nAccept:*/*\r\n\r\n", testPeerHost);
      testClient.expect_ready_to_send(testHttpRequest);
      testClient.expect_error(connection_reset_error_code);
      testClient.expect_ready_to_connect(testConfig);
      EXPECT_EQ(std::future_status::ready, testClient.wait_for(test_good_request_timeout));
   }
   /// Do not keep alive
   {
      constexpr auto testResponseBody = std::string_view{R"raw({"test":"response"})raw"};
      EXPECT_CALL(testRestServer, should_accept_socket()).WillOnce(testing::Return(true));
      EXPECT_CALL(testRestServer, should_pass_handshake()).WillOnce(testing::Return(true));
      EXPECT_CALL(testRestServer, handle_request(testing::_, testing::_))
         .WillOnce(
            [&] (auto const &testRequest, auto &testResponse)
            {
               auto testHeaders = std::map<std::string_view, std::string_view>
               {
                  {"Accept", "*/*"},
                  {"Host", testPeerHost},
               };
               EXPECT_HTTP_REQUEST(testRequest, boost::beast::http::verb::get, "/", testHeaders, "");

               testResponse.clear();
               testResponse.result(boost::beast::http::status::ok);
               testResponse.version(testRequest.version());
               testResponse.keep_alive(true);
               testResponse.set(boost::beast::http::field::content_type, testContentType);
               testResponse.body() = testResponseBody;
               testResponse.prepare_payload();
               testResponse.content_length(testResponse.body().size());
               return true;
            }
         )
      ;
      EXPECT_CALL(testRestServer, should_keep_alive()).WillOnce(testing::Return(false));
      test_tcp_client testClient{testThread};
      auto const testHttpRequest = std::format("GET / HTTP/1.1\r\nHost:{}\r\nAccept:*/*\r\n\r\n", testPeerHost);
      testClient.expect_ready_to_send(testHttpRequest);
      auto const testHttpResponse = std::format(
         "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\n\r\n{}",
         testContentType,
         testResponseBody.size(),
         testResponseBody
      );
      testClient.expect_recv(
         testHttpResponse,
         [
            &testClient,
            &testHttpRequest,
            &connection_reset_error_code
         ] ()
         {
            testClient.expect_error_on_send(testHttpRequest, connection_reset_error_code);
         }
      );
      testClient.expect_ready_to_connect(testConfig);
      EXPECT_EQ(std::future_status::ready, testClient.wait_for(test_good_request_timeout));
   }
   /// CRUD
   {
      EXPECT_CALL(testRestServer, should_accept_socket()).WillOnce(testing::Return(true));
      EXPECT_CALL(testRestServer, should_pass_handshake()).WillOnce(testing::Return(true));
      test_tcp_client testClient{testThread};
      auto const testDisconnect = [&testRestServer, &testClient] ()
      {
         testClient.expect_disconnect();
      };
      auto const testInternalCleanupCheck = [&testRestServer, &testClient, &testDisconnect, testPeerHost, &testContentType] ()
      {
         EXPECT_CALL(testRestServer, handle_request(testing::_, testing::_))
            .WillOnce(
               [testPeerHost, testContentType] (auto const &testRequest, auto &testResponse)
               {
                  auto testHeaders = std::map<std::string_view, std::string_view>
                  {
                     {"Accept", "*/*"},
                     {"Host", testPeerHost},
                  };
                  EXPECT_HTTP_REQUEST(testRequest, boost::beast::http::verb::get, "/", testHeaders, "");

                  testResponse.clear();
                  testResponse.result(boost::beast::http::status::ok);
                  testResponse.version(testRequest.version());
                  testResponse.keep_alive(true);
                  testResponse.set(boost::beast::http::field::content_type, testContentType);
                  testResponse.body() = "{}";
                  testResponse.prepare_payload();
                  testResponse.content_length(testResponse.body().size());
                  return true;
               }
            )
         ;
         EXPECT_CALL(testRestServer, should_keep_alive()).WillOnce(testing::Return(true));
         auto const testHttpRequest = std::format("GET / HTTP/1.1\r\nHost:{}\r\nAccept:*/*\r\n\r\n", testPeerHost);
         auto const testHttpResponse = std::format("HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: 2\r\n\r\n{{}}", testContentType);
         testClient.expect_recv(testHttpResponse, testDisconnect);
         testClient.expect_ready_to_send(testHttpRequest);
      };
      auto const testDeleteRequest = [&testRestServer, &testClient, &testInternalCleanupCheck, testPeerHost, &testContentType] ()
      {
         constexpr auto testUrlPath = std::string_view{"/test_method/delete"};
         constexpr auto testUrlQuery = std::string_view{"?test_operation=delete"};
         constexpr auto testRequestBody = std::string_view{R"raw({"test_operation":"delete"})raw"};
         constexpr auto testResponseBody = std::string_view{R"raw({"test_result":"deleted"})raw"};
         EXPECT_CALL(testRestServer, handle_request(testing::_, testing::_))
            .WillOnce(
               [
                  testPeerHost,
                  testUrlPath,
                  testUrlQuery,
                  testContentType,
                  testRequestBody,
                  testResponseBody
               ] (auto const &testRequest, auto &testResponse)
               {
                  std::string const testTarget = std::string{}.append(testUrlPath).append(testUrlQuery);
                  auto const testContentLength = std::to_string(testRequestBody.size());
                  auto testHeaders = std::map<std::string_view, std::string_view>
                  {
                     {"Accept", "*/*"},
                     {"Content-Length", testContentLength},
                     {"Content-Type", testContentType},
                     {"Host", testPeerHost},
                     {"Test-Method", "DELETE"},
                     {"Test-Operation", "DELETE"},
                  };
                  EXPECT_HTTP_REQUEST(testRequest, boost::beast::http::verb::delete_, testTarget, testHeaders, testRequestBody);

                  testResponse.clear();
                  testResponse.result(boost::beast::http::status::accepted);
                  testResponse.version(testRequest.version());
                  testResponse.keep_alive(true);
                  testResponse.set(boost::beast::http::field::content_type, testContentType);
                  testResponse.body() = testResponseBody;
                  testResponse.prepare_payload();
                  testResponse.content_length(testResponse.body().size());
                  return true;
               }
            )
         ;
         EXPECT_CALL(testRestServer, should_keep_alive()).WillOnce(testing::Return(true));
         auto const testHttpRequest = std::format(
            "DELETE {}{} HTTP/1.1\r\nHost:{}\r\nContent-Length:{}\r\nContent-Type:{}\r\nAccept:*/*\r\nTest-Method:DELETE\r\nTest-Operation:DELETE\r\n\r\n{}",
            testUrlPath,
            testUrlQuery,
            testPeerHost,
            testRequestBody.size(),
            testContentType,
            testRequestBody
         );
         auto const testHttpResponse = std::format(
            "HTTP/1.1 202 Accepted\r\nContent-Type: {}\r\nContent-Length: {}\r\n\r\n{}",
            testContentType,
            testResponseBody.size(),
            testResponseBody
         );
         testClient.expect_recv(testHttpResponse, testInternalCleanupCheck);
         testClient.expect_ready_to_send(testHttpRequest);
      };
      auto const testUpdateRequest = [&testRestServer, &testClient, &testDeleteRequest, testPeerHost, &testContentType] ()
      {
         constexpr auto testUrlPath = std::string_view{"test_method/put"};
         constexpr auto testUrlQuery = std::string_view{"test_operation=update"};
         constexpr auto testRequestBody = std::string_view{R"raw({"test_operation":"update"})raw"};
         constexpr auto testResponseBody = std::string_view{R"raw({"test_result":"updated"})raw"};
         EXPECT_CALL(testRestServer, handle_request(testing::_, testing::_))
            .WillOnce(
               [
                  testPeerHost,
                  testUrlPath,
                  testUrlQuery,
                  testContentType,
                  testRequestBody,
                  testResponseBody
               ] (auto const &testRequest, auto &testResponse)
               {
                  std::string const testTarget = std::string{"/"}.append(testUrlPath).append("?").append(testUrlQuery);
                  auto const testContentLength = std::to_string(testRequestBody.size());
                  auto testHeaders = std::map<std::string_view, std::string_view>
                  {
                     {"Accept", "*/*"},
                     {"Host", testPeerHost},
                     {"Content-Length", testContentLength},
                     {"Content-Type", testContentType},
                     {"Test-Method", "PUT"},
                     {"Test-Operation", "UPDATE"},
                  };
                  EXPECT_HTTP_REQUEST(testRequest, boost::beast::http::verb::put, testTarget, testHeaders, testRequestBody);

                  testResponse.clear();
                  testResponse.result(boost::beast::http::status::ok);
                  testResponse.version(testRequest.version());
                  testResponse.keep_alive(true);
                  testResponse.set(boost::beast::http::field::content_type, testContentType);
                  testResponse.body() = testResponseBody;
                  testResponse.prepare_payload();
                  testResponse.content_length(testResponse.body().size());
                  return true;
               }
            )
         ;
         EXPECT_CALL(testRestServer, should_keep_alive()).WillOnce(testing::Return(true));
         auto const testHttpRequest = std::format(
            "PUT /{}?{} HTTP/1.1\r\nHost:{}\r\nContent-Length:{}\r\nContent-Type:{}\r\nAccept:*/*\r\nTest-Method:PUT\r\nTest-Operation:UPDATE\r\n\r\n{}",
            testUrlPath,
            testUrlQuery,
            testPeerHost,
            testRequestBody.size(),
            testContentType,
            testRequestBody
         );
         auto const testHttpResponse = std::format(
            "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\n\r\n{}",
            testContentType,
            testResponseBody.size(),
            testResponseBody
         );
         testClient.expect_recv(testHttpResponse, testDeleteRequest);
         testClient.expect_ready_to_send(testHttpRequest);
      };
      auto const testReadRequest = [&testRestServer, &testClient, &testUpdateRequest, testPeerHost, &testContentType] ()
      {
         constexpr auto testUrlPath = std::string_view{"test_method/get"};
         constexpr auto testUrlQuery = std::string_view{"test_operation=read"};
         constexpr auto testResponseBody = std::string_view{R"raw({"test_result":"read"})raw"};
         EXPECT_CALL(testRestServer, handle_request(testing::_, testing::_))
            .WillOnce(
               [
                  testPeerHost,
                  testUrlPath,
                  testUrlQuery,
                  testContentType,
                  testResponseBody
               ] (auto const &testRequest, auto &testResponse)
               {
                  std::string const testTarget = std::string{"/"}.append(testUrlPath).append("?").append(testUrlQuery);
                  auto testHeaders = std::map<std::string_view, std::string_view>
                  {
                     {"Accept", "*/*"},
                     {"Host", testPeerHost},
                     {"Test-Method", "GET"},
                     {"Test-Operation", "READ"},
                  };
                  EXPECT_HTTP_REQUEST(testRequest, boost::beast::http::verb::get, testTarget, testHeaders, "");

                  testResponse.clear();
                  testResponse.result(boost::beast::http::status::ok);
                  testResponse.version(testRequest.version());
                  testResponse.keep_alive(true);
                  testResponse.set(boost::beast::http::field::content_type, testContentType);
                  testResponse.body() = testResponseBody;
                  testResponse.prepare_payload();
                  testResponse.content_length(testResponse.body().size());
                  return true;
               }
            )
         ;
         EXPECT_CALL(testRestServer, should_keep_alive()).WillOnce(testing::Return(true));
         auto const testHttpRequest = std::format(
            "GET /{}?{} HTTP/1.1\r\nHost:{}\r\nAccept:*/*\r\nTest-Method:GET\r\nTest-Operation:READ\r\n\r\n{}",
            testUrlPath,
            testUrlQuery,
            testPeerHost,
            testContentType
         );
         auto const testHttpResponse = std::format(
            "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\n\r\n{}",
            testContentType,
            testResponseBody.size(),
            testResponseBody
         );
         testClient.expect_recv(testHttpResponse, testUpdateRequest);
         testClient.expect_ready_to_send(testHttpRequest);
      };
      auto const testCreateRequest = [&testRestServer, &testClient, &testReadRequest, testPeerHost, &testContentType] ()
      {
         constexpr auto testUrlPath = std::string_view{"test_method/post"};
         constexpr auto testUrlQuery = std::string_view{"test_operation=create"};
         constexpr auto testRequestBody = std::string_view{R"raw({"test_operation":"create"})raw"};
         constexpr auto testResponseBody = std::string_view{R"raw({"test_result":"created"})raw"};
         EXPECT_CALL(testRestServer, handle_request(testing::_, testing::_))
            .WillOnce(
               [
                  testPeerHost,
                  testUrlPath,
                  testUrlQuery,
                  testContentType,
                  testRequestBody,
                  testResponseBody
               ] (auto const &testRequest, auto &testResponse)
               {
                  std::string const testTarget = std::string{"/"}.append(testUrlPath).append("?").append(testUrlQuery);
                  auto const testContentLength = std::to_string(testRequestBody.size());
                  auto testHeaders = std::map<std::string_view, std::string_view>
                  {
                     {"Accept", "*/*"},
                     {"Content-Length", testContentLength},
                     {"Content-Type", testContentType},
                     {"Host", testPeerHost},
                     {"Test-Method", "POST"},
                     {"Test-Operation", "CREATE"},
                  };
                  EXPECT_HTTP_REQUEST(testRequest, boost::beast::http::verb::post, testTarget, testHeaders, testRequestBody);

                  testResponse.clear();
                  testResponse.result(boost::beast::http::status::created);
                  testResponse.version(testRequest.version());
                  testResponse.keep_alive(true);
                  testResponse.set(boost::beast::http::field::content_type, testContentType);
                  testResponse.body() = testResponseBody;
                  testResponse.prepare_payload();
                  testResponse.content_length(testResponse.body().size());
                  return true;
               }
            )
         ;
         EXPECT_CALL(testRestServer, should_keep_alive()).WillOnce(testing::Return(true));
         auto const testHttpRequest = std::format(
            "POST /{}?{} HTTP/1.1\r\nHost:{}\r\nContent-Length:{}\r\nContent-Type:{}\r\nAccept:*/*\r\nTest-Method:POST\r\nTest-Operation:CREATE\r\n\r\n{}",
            testUrlPath,
            testUrlQuery,
            testPeerHost,
            testRequestBody.size(),
            testContentType,
            testRequestBody
         );
         auto const testHttpResponse = std::format(
            "HTTP/1.1 201 Created\r\nContent-Type: {}\r\nContent-Length: {}\r\n\r\n{}",
            testContentType,
            testResponseBody.size(),
            testResponseBody
         );
         testClient.expect_recv(testHttpResponse, testReadRequest);
         testClient.expect_ready_to_send(testHttpRequest);
      };
      testCreateRequest();
      testClient.expect_ready_to_connect(testConfig);
      EXPECT_EQ(std::future_status::ready, testClient.wait_for(test_good_request_timeout));
   }
}

}
