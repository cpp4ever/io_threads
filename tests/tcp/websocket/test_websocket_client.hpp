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

#include "tcp/websocket/test_websocket_server.hpp"

#include <io_threads/system_network_interfaces.hpp>
#include <io_threads/tcp_client_config.hpp>
#include <io_threads/websocket_client_config.hpp>

namespace io_threads::tests
{

template<typename test_stream, typename test_client>
void test_websocket_client(test_client &testClient)
{
   auto const testConnectivityIssueErrorCodeMatcher
   {
      testing::AnyOf(
#if (defined(__linux__))
         std::make_error_code(std::errc::connection_aborted),
         std::make_error_code(std::errc::connection_reset)
#elif (defined(_WIN32) || defined(_WIN64))
         std::error_code{WSAECONNABORTED, std::system_category()},
         std::error_code{WSAECONNRESET, std::system_category()}
#endif
      ),
   };
   system_network_interfaces testNetworkInterfaces{};
   auto const testLoopbackNetworkInterface = testNetworkInterfaces.loopback();
   ASSERT_TRUE(testLoopbackNetworkInterface.has_value());
   auto testNetworkInterfaceIps = std::vector<std::string_view>{};
   if (true == testLoopbackNetworkInterface.value().ipv4().has_value())
   {
      auto const testNetworkInterfaceIp = std::string_view{testLoopbackNetworkInterface->ipv4().value()};
      ASSERT_FALSE(testNetworkInterfaceIp.empty());
      testNetworkInterfaceIps.push_back(testNetworkInterfaceIp);
   }
   if (true == testLoopbackNetworkInterface.value().ipv6().has_value())
   {
      auto const testNetworkInterfaceIp = std::string_view{testLoopbackNetworkInterface->ipv6().value()};
      ASSERT_FALSE(testNetworkInterfaceIp.empty());
      testNetworkInterfaceIps.push_back(testNetworkInterfaceIp);
   }
   ASSERT_FALSE(testNetworkInterfaceIps.empty());
   constexpr auto testTimeout = std::chrono::seconds{5};
   constexpr auto testTcpKeepAlive = tcp_keep_alive
   {
      .idleTimeout = testTimeout,
      .probeTimeout = testTimeout,
      .probesCount = 0,
   };
   for (auto const &testPeerHost : testNetworkInterfaceIps)
   {
      testing::StrictMock<test_websocket_server<test_stream>> testServer{boost::asio::ip::make_address(testPeerHost)};
      std::error_code testErrorCode{};
      auto const testSocketAddress = make_socket_address(testPeerHost, testServer.local_port(), testErrorCode);
      ASSERT_FALSE(testErrorCode) << testErrorCode.value() << ": " << testErrorCode.message();
      ASSERT_TRUE(testSocketAddress.has_value());
      auto const testTcpConfig =
         tcp_client_config{tcp_client_address{testLoopbackNetworkInterface.value(), testSocketAddress.value()}}
         .with_keep_alive(testTcpKeepAlive)
         .with_nodelay()
         .with_user_timeout(testTimeout)
      ;
      auto const testWebsocketConfig = websocket_client_config{"/test?name=websocket"};
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
                  auto const testInboundMessage = std::string_view
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
                  auto const testInboundMessage = std::string_view
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
                  auto const testInboundMessage = std::string_view
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
               testClient.expect_disconnect();
            }
         );
         testClient.expect_ready_to_send(testRequest);
         testClient.expect_ready_to_handshake(testWebsocketConfig);
         testClient.expect_ready_to_connect(testTcpConfig);
         ASSERT_EQ(std::future_status::ready, testClient.wait_for(testTimeout));
      }
   }
}

}
