/*
   Part of the webThread Project (https://github.com/cpp4ever/webthread), under the MIT License
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

#pragma once

#include "tcp/websocket/test_websocket_server.hpp"

#include <io_threads/system_network_interfaces.hpp>
#include <io_threads/tcp_client_config.hpp>
#include <io_threads/time.hpp>
#include <io_threads/websocket_client_config.hpp>

namespace io_threads::tests
{

template<typename test_stream, typename test_client>
void test_websocket_client(test_client &testClient)
{
   testClient.expect_disconnect(); ///< disconnect without connection
   auto const testConnectivityIssueErrorCodeMatcher
   {
      testing::AnyOf(
#if (defined(__linux__))
         std::make_error_code(std::errc::connection_aborted),
         std::make_error_code(std::errc::connection_reset)
#elif (defined(_WIN32) || defined(_WIN64))
         std::error_code{WSAECONNABORTED, std::system_category(),},
         std::error_code{WSAECONNRESET, std::system_category(),}
#endif
      ),
   };
   system_network_interfaces testNetworkInterfaces{};
   auto const &testLoopbackNetworkInterface{testNetworkInterfaces.loopback(),};
   ASSERT_TRUE(testLoopbackNetworkInterface.has_value());
   std::vector<std::string_view> testNetworkInterfaceIps{};
   if (true == testLoopbackNetworkInterface.value().ipv4().has_value())
   {
      std::string_view const testNetworkInterfaceIp{testLoopbackNetworkInterface->ipv4().value()};
      ASSERT_FALSE(testNetworkInterfaceIp.empty());
      testNetworkInterfaceIps.push_back(testNetworkInterfaceIp);
   }
   if (true == testLoopbackNetworkInterface.value().ipv6().has_value())
   {
      std::string_view const testNetworkInterfaceIp{testLoopbackNetworkInterface->ipv6().value()};
      ASSERT_FALSE(testNetworkInterfaceIp.empty());
      testNetworkInterfaceIps.push_back(testNetworkInterfaceIp);
   }
   ASSERT_FALSE(testNetworkInterfaceIps.empty());
   constexpr std::chrono::seconds testTimeout{1,};
   constexpr tcp_keep_alive testTcpKeepAlive
   {
      .idleTimeout = testTimeout,
      .probeTimeout = testTimeout,
      .probesCount = 0,
   };
   for (auto const &testPeerHost : testNetworkInterfaceIps)
   {
      testing::StrictMock<test_websocket_server<test_stream>> testServer{boost::asio::ip::make_address(testPeerHost),};
      std::error_code testErrorCode{};
      auto const testSocketAddress{make_socket_address(testPeerHost, testServer.local_port(), testErrorCode),};
      ASSERT_FALSE(testErrorCode) << testErrorCode.value() << ": " << testErrorCode.message();
      ASSERT_TRUE(testSocketAddress.has_value());
      auto const testTcpConfig
      {
         tcp_client_config{tcp_client_address{testLoopbackNetworkInterface.value(), testSocketAddress.value(),},}
            .with_keep_alive(testTcpKeepAlive)
            .with_nodelay()
            .with_user_timeout(testTimeout)
         ,
      };
      websocket_client_config const testWebsocketConfig{"/test?name=websocket",};
      /// Disconnect on socket accept
      {
         EXPECT_CALL(testServer, should_accept_socket()).WillOnce(testing::Return(false));
         testClient.expect_error(testConnectivityIssueErrorCodeMatcher);
         testClient.expect_ready_to_send(R"raw({"test_request":"disconnect_on_socket_accept"})raw");
         testClient.expect_ready_to_connect(testTcpConfig);
         ASSERT_EQ(std::future_status::ready, testClient.wait_for(testTimeout));
      }
      /// Disconnect on handshake
      {
         EXPECT_CALL(testServer, should_accept_socket()).WillOnce(testing::Return(true));
         EXPECT_CALL(testServer, should_pass_handshake()).WillOnce(testing::Return(false));
         testClient.expect_error(testConnectivityIssueErrorCodeMatcher);
         testClient.expect_ready_to_send(R"raw({"test_request":"disconnect_on_handshake"})raw");
         testClient.expect_ready_to_handshake(testWebsocketConfig);
         testClient.expect_ready_to_connect(testTcpConfig);
         ASSERT_EQ(std::future_status::ready, testClient.wait_for(testTimeout));
      }
      /// Disconnect on websocket accept
      {
         EXPECT_CALL(testServer, should_accept_socket()).WillOnce(testing::Return(true));
         EXPECT_CALL(testServer, should_pass_handshake()).WillOnce(testing::Return(true));
         EXPECT_CALL(testServer, should_accept_websocket()).WillOnce(testing::Return(false));
         testClient.expect_error(testConnectivityIssueErrorCodeMatcher);
         testClient.expect_ready_to_send(R"raw({"test_request":"disconnect_on_websocket_accept"})raw");
         testClient.expect_ready_to_handshake(testWebsocketConfig);
         testClient.expect_ready_to_connect(testTcpConfig);
         ASSERT_EQ(std::future_status::ready, testClient.wait_for(testTimeout));
      }
      /// Disconnect on message
      {
         EXPECT_CALL(testServer, should_accept_socket()).WillOnce(testing::Return(true));
         EXPECT_CALL(testServer, should_pass_handshake()).WillOnce(testing::Return(true));
         EXPECT_CALL(testServer, should_accept_websocket()).WillOnce(testing::Return(true));
         std::string const testRequest{R"raw({"test_request":"disconnect_on_message"})raw",};
         EXPECT_CALL(testServer, handle_message(testing::_, testing::_))
            .WillOnce(
               [testRequest] (auto const &testInboundBuffer, auto &)
               {
                  std::string_view const testInboundMessage
                  {
                     static_cast<char const *>(testInboundBuffer.data().data()),
                     testInboundBuffer.data().size(),
                  };
                  EXPECT_EQ(testInboundMessage, testRequest);
                  return false;
               }
            )
         ;
         testClient.expect_error(testConnectivityIssueErrorCodeMatcher);
         testClient.expect_ready_to_send(testRequest);
         testClient.expect_ready_to_handshake(testWebsocketConfig);
         testClient.expect_ready_to_connect(testTcpConfig);
         ASSERT_EQ(std::future_status::ready, testClient.wait_for(testTimeout));
      }
      /// Do not keep alive
      {
         EXPECT_CALL(testServer, should_accept_socket()).WillOnce(testing::Return(true));
         EXPECT_CALL(testServer, should_pass_handshake()).WillOnce(testing::Return(true));
         EXPECT_CALL(testServer, should_accept_websocket()).WillOnce(testing::Return(true));
         std::string const testRequest{R"raw({"test_request":"do_not_keep_alive"})raw",};
         std::string const testResponse{R"raw({"test_response":"do_not_keep_alive"})raw",};
         EXPECT_CALL(testServer, handle_message(testing::_, testing::_))
            .WillOnce(
               [testRequest, testResponse] (auto const &testInboundBuffer, auto &testOutboundBuffer)
               {
                  std::string_view const testInboundMessage
                  {
                     static_cast<char const *>(testInboundBuffer.data().data()),
                     testInboundBuffer.data().size(),
                  };
                  EXPECT_EQ(testInboundMessage, testRequest);
                  testOutboundBuffer.append(testResponse);
                  return true;
               }
            )
         ;
         EXPECT_CALL(testServer, should_keep_alive()).WillOnce(testing::Return(false));
         testClient.expect_recv(
            testResponse,
            [
               &testClient,
               testRequest,
               &testConnectivityIssueErrorCodeMatcher
            ] ()
            {
               testClient.expect_error(testConnectivityIssueErrorCodeMatcher);
               testClient.expect_ready_to_send(testRequest);
            }
         );
         testClient.expect_ready_to_send(testRequest);
         testClient.expect_ready_to_handshake(testWebsocketConfig);
         testClient.expect_ready_to_connect(testTcpConfig);
         ASSERT_EQ(std::future_status::ready, testClient.wait_for(testTimeout));
      }
      /// Connection close
      {
         EXPECT_CALL(testServer, should_accept_socket()).WillOnce(testing::Return(true));
         EXPECT_CALL(testServer, should_pass_handshake()).WillOnce(testing::Return(true));
         EXPECT_CALL(testServer, should_accept_websocket()).WillOnce(testing::Return(true));
         std::string const testRequest{R"raw({"test_request":"connection_close"})raw",};
         std::string const testResponse{R"raw({"test_response":"connection_close"})raw",};
         EXPECT_CALL(testServer, handle_message(testing::_, testing::_))
            .WillOnce(
               [testRequest, testResponse] (auto const &testInboundBuffer, auto &testOutboundBuffer)
               {
                  std::string_view const testInboundMessage
                  {
                     static_cast<char const *>(testInboundBuffer.data().data()),
                     testInboundBuffer.data().size(),
                  };
                  EXPECT_EQ(testInboundMessage, testRequest);
                  testOutboundBuffer.append(testResponse);
                  return true;
               }
            )
         ;
         EXPECT_CALL(testServer, should_keep_alive()).WillOnce(testing::Return(true));
         testClient.expect_recv(
            testResponse,
            [&testClient] ()
            {
               testClient.expect_close();
            }
         );
         testClient.expect_ready_to_send(testRequest);
         testClient.expect_ready_to_handshake(testWebsocketConfig);
         testClient.expect_ready_to_connect(testTcpConfig);
         ASSERT_EQ(std::future_status::ready, testClient.wait_for(testTimeout));
      }
      /// Deferred connect
      {
         EXPECT_CALL(testServer, should_accept_socket()).WillOnce(testing::Return(true));
         EXPECT_CALL(testServer, should_pass_handshake()).WillOnce(testing::Return(true));
         EXPECT_CALL(testServer, should_accept_websocket()).WillOnce(testing::Return(true));
         std::string const testRequest{R"raw({"test_request":"deferred_connect"})raw",};
         std::string const testResponse{R"raw({"test_response":"deferred_connect"})raw",};
         testClient.expect_ready_to_connect_deferred(steady_clock::now() + std::chrono::milliseconds{10,}); ///< must be cancelled due to the following call
         testClient.expect_ready_to_connect_deferred(steady_clock::now() + std::chrono::hours{1,}); ///< must cancel previous deferred task
         ASSERT_EQ(std::future_status::timeout, testClient.wait_for(std::chrono::milliseconds{10,}));
         auto const testConnectTime{steady_clock::now() + std::chrono::milliseconds{100,},};
         EXPECT_CALL(testServer, handle_message(testing::_, testing::_))
            .WillOnce(
               [testRequest, testResponse, testConnectTime] (auto const &testInboundBuffer, auto &testOutboundBuffer)
               {
                  EXPECT_GT(steady_clock::now(), testConnectTime);
                  std::string_view const testInboundMessage
                  {
                     static_cast<char const *>(testInboundBuffer.data().data()),
                     testInboundBuffer.data().size(),
                  };
                  EXPECT_EQ(testInboundMessage, testRequest);
                  testOutboundBuffer.append(testResponse);
                  return true;
               }
            )
         ;
         EXPECT_CALL(testServer, should_keep_alive()).WillOnce(testing::Return(true));
         testClient.expect_recv(
            testResponse,
            [&testClient] ()
            {
               testClient.expect_close();
            }
         );
         testClient.expect_ready_to_send(testRequest);
         testClient.expect_ready_to_handshake(testWebsocketConfig);
         testClient.executor().execute(
            [&testClient, testTcpConfig, testConnectTime] ()
            {
               testClient.expect_ready_to_connect_deferred(testTcpConfig, testConnectTime);
            }
         );
         ASSERT_EQ(std::future_status::ready, testClient.wait_for(testTimeout));
      }
      /// Deferred send
      {
         EXPECT_CALL(testServer, should_accept_socket()).WillOnce(testing::Return(true));
         EXPECT_CALL(testServer, should_pass_handshake()).WillOnce(testing::Return(true));
         EXPECT_CALL(testServer, should_accept_websocket()).WillOnce(testing::Return(true));
         std::string const testRequest{R"raw({"test_request":"deferred_send"})raw",};
         std::string const testResponse{R"raw({"test_response":"deferred_send"})raw",};
         testClient.expect_ready_to_send_deferred(steady_clock::now() + std::chrono::milliseconds{10,});
         auto const testSendTime{steady_clock::now() + std::chrono::milliseconds{100,},};
         EXPECT_CALL(testServer, handle_message(testing::_, testing::_))
            .WillOnce(
               [testRequest, testResponse, testSendTime] (auto const &testInboundBuffer, auto &testOutboundBuffer)
               {
                  EXPECT_GT(steady_clock::now(), testSendTime);
                  std::string_view const testInboundMessage
                  {
                     static_cast<char const *>(testInboundBuffer.data().data()),
                     testInboundBuffer.data().size(),
                  };
                  EXPECT_EQ(testInboundMessage, testRequest);
                  testOutboundBuffer.append(testResponse);
                  return true;
               }
            )
         ;
         EXPECT_CALL(testServer, should_keep_alive()).WillOnce(testing::Return(true));
         testClient.expect_recv(
            testResponse,
            [&testClient] ()
            {
               testClient.expect_close();
            }
         );
         testClient.expect_ready_to_send(
            [&testClient, testRequest, testSendTime] ()
            {
               testClient.expect_ready_to_send_deferred(testRequest, testSendTime);
            }
         );
         testClient.expect_ready_to_handshake(testWebsocketConfig);
         testClient.expect_ready_to_connect(testTcpConfig);
         ASSERT_EQ(std::future_status::ready, testClient.wait_for(testTimeout));
      }
   }
}

}
