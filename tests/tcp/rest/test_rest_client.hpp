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

#include "tcp/rest/test_rest_server.hpp"

#include <io_threads/system_network_interfaces.hpp>
#include <io_threads/tcp_client_config.hpp>
#include <io_threads/tcp_client_thread.hpp>

#include <format>

namespace io_threads::tests
{

template<typename test_stream, typename test_client>
void test_rest_client(tcp_client_thread const testThread, test_client &testClient)
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
   if (true == testLoopbackNetworkInterface.value().ip_v4().has_value())
   {
      auto const testNetworkInterfaceIp = std::string_view{testLoopbackNetworkInterface->ip_v4().value()};
      ASSERT_FALSE(testNetworkInterfaceIp.empty());
      testNetworkInterfaceIps.push_back(testNetworkInterfaceIp);
   }
   if (true == testLoopbackNetworkInterface.value().ip_v6().has_value())
   {
      auto const testNetworkInterfaceIp = std::string_view{testLoopbackNetworkInterface->ip_v6().value()};
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
      testing::StrictMock<test_rest_server<test_stream>> testServer{boost::asio::ip::make_address(testPeerHost)};
      std::error_code testErrorCode{};
      auto const testSocketAddress = make_socket_address(testPeerHost, testServer.local_port(), testErrorCode);
      ASSERT_FALSE(testErrorCode) << testErrorCode.value() << ": " << testErrorCode.message();
      ASSERT_TRUE(testSocketAddress.has_value());
      auto const testConfig =
         tcp_client_config{tcp_client_address{testLoopbackNetworkInterface.value(), testSocketAddress.value()}}
         .with_keep_alive(testTcpKeepAlive)
         .with_nodelay()
         .with_user_timeout(testTimeout)
      ;
      auto const testContentType = std::string{"application/json"};
      /// Disconnect on socket accept
      {
         EXPECT_CALL(testServer, should_accept_socket()).WillOnce(testing::Return(false));
         testClient.expect_error(testConnectivityIssueErrorCodeMatcher);
         testClient.expect_ready_to_send(std::format("GET / HTTP/1.1\r\nHost:{}\r\nAccept:*/*\r\n\r\n", testPeerHost));
         testClient.expect_ready_to_connect(testConfig);
         ASSERT_EQ(std::future_status::ready, testClient.wait_for(testTimeout));
      }
      /// Disconnect on handshake
      {
         EXPECT_CALL(testServer, should_accept_socket()).WillOnce(testing::Return(true));
         EXPECT_CALL(testServer, should_pass_handshake()).WillOnce(testing::Return(false));
         testClient.expect_error(testConnectivityIssueErrorCodeMatcher);
         testClient.expect_ready_to_send(std::format("GET / HTTP/1.1\r\nHost:{}\r\nAccept:*/*\r\n\r\n", testPeerHost));
         testClient.expect_ready_to_connect(testConfig);
         ASSERT_EQ(std::future_status::ready, testClient.wait_for(testTimeout));
      }
      /// Disconnect on request
      {
         EXPECT_CALL(testServer, should_accept_socket()).WillOnce(testing::Return(true));
         EXPECT_CALL(testServer, should_pass_handshake()).WillOnce(testing::Return(true));
         EXPECT_CALL(testServer, handle_request(testing::_, testing::_))
            .WillOnce(
               [testPeerHost] (auto const &testRequest, auto &)
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
         testClient.expect_error(testConnectivityIssueErrorCodeMatcher);
         testClient.expect_ready_to_send(std::format("GET / HTTP/1.1\r\nHost:{}\r\nAccept:*/*\r\n\r\n", testPeerHost));
         testClient.expect_ready_to_connect(testConfig);
         ASSERT_EQ(std::future_status::ready, testClient.wait_for(testTimeout));
      }
      /// Do not keep alive
      {
         constexpr auto testResponseBody = std::string_view{R"raw({"test":"response"})raw"};
         EXPECT_CALL(testServer, should_accept_socket()).WillOnce(testing::Return(true));
         EXPECT_CALL(testServer, should_pass_handshake()).WillOnce(testing::Return(true));
         EXPECT_CALL(testServer, handle_request(testing::_, testing::_))
            .WillOnce(
               [testPeerHost, &testContentType, testResponseBody] (auto const &testRequest, auto &testResponse)
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
         EXPECT_CALL(testServer, should_keep_alive()).WillOnce(testing::Return(false));
         auto const testHttpRequest = std::format("GET / HTTP/1.1\r\nHost:{}\r\nAccept:*/*\r\n\r\n", testPeerHost);
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
               &testConnectivityIssueErrorCodeMatcher
            ] ()
            {
               testClient.expect_error(testConnectivityIssueErrorCodeMatcher);
               testClient.expect_ready_to_send(testHttpRequest);
            }
         );
         testClient.expect_ready_to_send(testHttpRequest);
         testClient.expect_ready_to_connect(testConfig);
         ASSERT_EQ(std::future_status::ready, testClient.wait_for(testTimeout));
      }
      /// CRUD
      {
         EXPECT_CALL(testServer, should_accept_socket()).WillOnce(testing::Return(true));
         EXPECT_CALL(testServer, should_pass_handshake()).WillOnce(testing::Return(true));
         std::atomic_intptr_t testDisconnectStepLock{0,};
         auto const testDisconnect
         {
            [&testDisconnectStepLock, &testClient] ()
            {
               if (0 == testDisconnectStepLock.fetch_add(1, std::memory_order_release))
               {
                  return;
               }
               testClient.expect_disconnect();
            },
         };
         std::atomic_intptr_t testInternalCleanupCheckStepLock{0,};
         auto const testInternalCleanupCheck
         {
            [
               testThread,
               &testInternalCleanupCheckStepLock,
               &testServer,
               &testClient,
               &testDisconnect,
               testPeerHost,
               &testContentType
            ] ()
            {
               if (0 == testInternalCleanupCheckStepLock.fetch_add(1, std::memory_order_release))
               {
                  return;
               }
               EXPECT_CALL(testServer, handle_request(testing::_, testing::_))
                  .WillOnce(
                     [testPeerHost, &testContentType] (auto const &testRequest, auto &testResponse)
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
               EXPECT_CALL(testServer, should_keep_alive())
                  .WillOnce(
                     [testThread, &testDisconnect]
                     {
                        testThread.execute(testDisconnect);
                        return true;
                     }
                  )
               ;
               auto const testHttpRequest = std::format("GET / HTTP/1.1\r\nHost:{}\r\nAccept:*/*\r\n\r\n", testPeerHost);
               auto const testHttpResponse = std::format("HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: 2\r\n\r\n{{}}", testContentType);
               testClient.expect_recv(testHttpResponse, testDisconnect);
               testClient.expect_ready_to_send(testHttpRequest);
            },
         };
         std::atomic_intptr_t testDeleteRequestStepLock{0,};
         auto const testDeleteRequest
         {
            [
               testThread,
               &testDeleteRequestStepLock,
               &testServer,
               &testClient,
               &testInternalCleanupCheck,
               testPeerHost,
               &testContentType
            ] ()
            {
               if (0 == testDeleteRequestStepLock.fetch_add(1, std::memory_order_release))
               {
                  return;
               }
               constexpr auto testTarget = std::string_view{"/test_method/delete?test_operation=delete"};
               constexpr auto testRequestBody = std::string_view{R"raw({"test_operation":"delete"})raw"};
               constexpr auto testResponseBody = std::string_view{R"raw({"test_result":"deleted"})raw"};
               EXPECT_CALL(testServer, handle_request(testing::_, testing::_))
                  .WillOnce(
                     [
                        testPeerHost,
                        testTarget,
                        &testContentType,
                        testRequestBody,
                        testResponseBody
                     ] (auto const &testRequest, auto &testResponse)
                     {
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
               EXPECT_CALL(testServer, should_keep_alive())
                  .WillOnce(
                     [testThread, &testInternalCleanupCheck]
                     {
                        testThread.execute(testInternalCleanupCheck);
                        return true;
                     }
                  )
               ;
               auto const testHttpRequest = std::format(
                  "DELETE {} HTTP/1.1\r\nHost:{}\r\nContent-Length:{}\r\nContent-Type:{}\r\nAccept:*/*\r\nTest-Method:DELETE\r\nTest-Operation:DELETE\r\n\r\n{}",
                  testTarget,
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
            },
         };
         std::atomic_intptr_t testUpdateRequestStepLock{0,};
         auto const testUpdateRequest
         {
            [
               testThread,
               &testUpdateRequestStepLock,
               &testServer,
               &testClient,
               &testDeleteRequest,
               testPeerHost,
               &testContentType
            ] ()
            {
               if (0 == testUpdateRequestStepLock.fetch_add(1, std::memory_order_release))
               {
                  return;
               }
               constexpr auto testTarget = std::string_view{"/test_method/put?test_operation=update"};
               constexpr auto testRequestBody = std::string_view{R"raw({"test_operation":"update"})raw"};
               constexpr auto testResponseBody = std::string_view{R"raw({"test_result":"updated"})raw"};
               EXPECT_CALL(testServer, handle_request(testing::_, testing::_))
                  .WillOnce(
                     [
                        testPeerHost,
                        testTarget,
                        &testContentType,
                        testRequestBody,
                        testResponseBody
                     ] (auto const &testRequest, auto &testResponse)
                     {
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
               EXPECT_CALL(testServer, should_keep_alive())
                  .WillOnce(
                     [testThread, &testDeleteRequest]
                     {
                        testThread.execute(testDeleteRequest);
                        return true;
                     }
                  )
               ;
               auto const testHttpRequest = std::format(
                  "PUT {} HTTP/1.1\r\nHost:{}\r\nContent-Length:{}\r\nContent-Type:{}\r\nAccept:*/*\r\nTest-Method:PUT\r\nTest-Operation:UPDATE\r\n\r\n{}",
                  testTarget,
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
            },
         };
         std::atomic_intptr_t testReadRequestStepLock{0,};
         auto const testReadRequest
         {
            [
               testThread,
               &testReadRequestStepLock,
               &testServer,
               &testClient,
               &testUpdateRequest,
               testPeerHost,
               &testContentType
            ] ()
            {
               if (0 == testReadRequestStepLock.fetch_add(1, std::memory_order_release))
               {
                  return;
               }
               constexpr auto testTarget = std::string_view{"/test_method/get?test_operation=read"};
               constexpr auto testResponseBody = std::string_view{R"raw({"test_result":"read"})raw"};
               EXPECT_CALL(testServer, handle_request(testing::_, testing::_))
                  .WillOnce(
                     [
                        testPeerHost,
                        testTarget,
                        &testContentType,
                        testResponseBody
                     ] (auto const &testRequest, auto &testResponse)
                     {
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
               EXPECT_CALL(testServer, should_keep_alive())
                  .WillOnce(
                     [testThread, &testUpdateRequest]
                     {
                        testThread.execute(testUpdateRequest);
                        return true;
                     }
                  )
               ;
               auto const testHttpRequest = std::format(
                  "GET {} HTTP/1.1\r\nHost:{}\r\nAccept:*/*\r\nTest-Method:GET\r\nTest-Operation:READ\r\n\r\n{}",
                  testTarget,
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
            },
         };
         auto const testCreateRequest
         {
            [testThread, &testServer, &testClient, &testReadRequest, testPeerHost, &testContentType]()
            {
               constexpr auto testTarget = std::string_view{"/test_method/post?test_operation=create"};
               constexpr auto testRequestBody = std::string_view{R"raw({"test_operation":"create"})raw"};
               constexpr auto testResponseBody = std::string_view{R"raw({"test_result":"created"})raw"};
               EXPECT_CALL(testServer, handle_request(testing::_, testing::_))
                  .WillOnce(
                     [
                        testPeerHost,
                           testTarget,
                           &testContentType,
                           testRequestBody,
                           testResponseBody
                     ] (auto const &testRequest, auto &testResponse)
                     {
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
               EXPECT_CALL(testServer, should_keep_alive())
                  .WillOnce(
                     [testThread, &testReadRequest]
                     {
                        testThread.execute(testReadRequest);
                        return true;
                     }
                  )
               ;
               auto const testHttpRequest = std::format(
                  "POST {} HTTP/1.1\r\nHost:{}\r\nContent-Length:{}\r\nContent-Type:{}\r\nAccept:*/*\r\nTest-Method:POST\r\nTest-Operation:CREATE\r\n\r\n{}",
                  testTarget,
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
            },
         };
         testThread.execute(testCreateRequest);
         testClient.expect_ready_to_connect(testConfig);
         ASSERT_EQ(std::future_status::ready, testClient.wait_for(testTimeout));
         EXPECT_EQ(2, testDisconnectStepLock.load(std::memory_order_acquire));
         EXPECT_EQ(2, testInternalCleanupCheckStepLock.load(std::memory_order_acquire));
         EXPECT_EQ(2, testDeleteRequestStepLock.load(std::memory_order_acquire));
         EXPECT_EQ(2, testUpdateRequestStepLock.load(std::memory_order_acquire));
         EXPECT_EQ(2, testReadRequestStepLock.load(std::memory_order_acquire));
      }
   }
}

}
