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

#include "tcp/test_ssl_certificate.hpp"
#include "tcp/test_tcp_connect_timeout.hpp"
#include "tcp/test_tcp_server_context.hpp"
#include "tcp/websocket/test_websocket_client.hpp"
#include "testsuite.hpp"

#include <io_threads/wss_client.hpp>

namespace io_threads::tests
{

namespace
{

class wss_client_mock : public io_threads::wss_client
{
private:
   using super = io_threads::wss_client;

   struct internal_state final
   {
      std::promise<void> done{};
      std::future<void> doneFuture{done.get_future(),};
   };

public:
   using super::super;

   wss_client_mock &operator = (wss_client_mock &&) = delete;
   wss_client_mock &operator = (wss_client_mock const &) = delete;

   void expect_disconnect()
   {
      EXPECT_CALL(*this, io_frame_to_send())
         .WillOnce(
            [this] ()
            {
               expect_error(std::error_code{});
               ready_to_close(websocket_closure_reason::normal);
               return websocket_frame{};
            }
         )
      ;
      ready_to_send();
   }

   template<typename error_code_matcher>
   void expect_error(error_code_matcher &&errorCodeMatcher)
   {
      EXPECT_CALL(*this, io_disconnected(testing::_))
         .WillOnce(
            [this, errorCodeMatcher] (auto const errorCode)
            {
               m_lastOutboundMessage.clear();
               m_connected.store(false, std::memory_order_relaxed);
               super::io_disconnected(errorCode);
               EXPECT_THAT(errorCode, errorCodeMatcher) << errorCode.value() << ": " << errorCode.message();
               EXPECT_CALL(*this, io_frame_received(testing::_, testing::_)).Times(0);
               EXPECT_CALL(*this, io_frame_to_send()).Times(0);
               EXPECT_CALL(*this, io_disconnected(testing::_)).Times(0);
               EXPECT_CALL(*this, io_ready_to_connect()).Times(0);
               EXPECT_CALL(*this, io_ready_to_handshake()).Times(0);
               assert(nullptr != m_internalState);
               m_internalState->done.set_value();
            }
         )
      ;
   }

   void expect_ready_to_connect(tcp_client_config const &tcpClientConfig)
   {
      m_internalState = std::make_unique<internal_state>();
      EXPECT_CALL(*this, io_ready_to_connect()).WillOnce(testing::Return(tcpClientConfig));
      ready_to_connect();
   }

   void expect_ready_to_connect_deferred(system_time const testNotBeforeTime)
   {
      m_internalState = std::make_unique<internal_state>();
      ready_to_connect_deferred(testNotBeforeTime);
   }

   void expect_ready_to_connect_deferred(tcp_client_config const &testConfig, system_time const testNotBeforeTime)
   {
      m_internalState = std::make_unique<internal_state>();
      EXPECT_CALL(*this, io_ready_to_connect()).WillOnce(testing::Return(testConfig));
      ready_to_connect_deferred(testNotBeforeTime);
   }

   void expect_ready_to_handshake(websocket_client_config const &websocketClientConfig)
   {
      EXPECT_CALL(*this, io_ready_to_handshake()).WillOnce(testing::Return(websocketClientConfig));
   }

   void expect_ready_to_send(std::string const &outboundMssage)
   {
      EXPECT_CALL(*this, io_frame_to_send())
         .WillRepeatedly(
            [this, outboundMssage] ()
            {
               EXPECT_CALL(*this, io_frame_to_send()).WillRepeatedly(
                  [this] ()
                  {
                     EXPECT_CALL(*this, io_frame_to_send()).Times(0);
                     return websocket_frame{};
                  }
               );
               m_lastOutboundMessage = outboundMssage;
               return websocket_frame
               {
                  .bytes = std::bit_cast<std::byte *>(m_lastOutboundMessage.data()),
                  .bytesLength = m_lastOutboundMessage.size(),
                  .type = websocket_frame_type::text,
               };
            }
         )
      ;
      ready_to_send();
   }

   void expect_ready_to_send(std::function<void()> sendHandler)
   {
      ASSERT_TRUE(sendHandler);
      EXPECT_CALL(*this, io_frame_to_send())
         .WillOnce(
            [sendHandler] ()
            {
               sendHandler();
               return websocket_frame{};
            }
         )
      ;
      ready_to_send();
   }

   void expect_ready_to_send_deferred(system_time const testNotBeforeTime)
   {
      ready_to_send_deferred(testNotBeforeTime);
   }

   void expect_ready_to_send_deferred(std::string outboundMessage, system_time const testNotBeforeTime)
   {
      EXPECT_CALL(*this, io_frame_to_send())
         .WillRepeatedly(
            [this, outboundMessage = std::move(outboundMessage)] ()
            {
               EXPECT_CALL(*this, io_frame_to_send()).WillRepeatedly(
                  [this] ()
                  {
                     EXPECT_CALL(*this, io_frame_to_send()).Times(0);
                     return websocket_frame{};
                  }
               );
               m_lastOutboundMessage = std::move(outboundMessage);
               return websocket_frame
               {
                  .bytes = std::bit_cast<std::byte *>(m_lastOutboundMessage.data()),
                  .bytesLength = m_lastOutboundMessage.size(),
                  .type = websocket_frame_type::text,
               };
            }
         )
      ;
      ready_to_send_deferred(testNotBeforeTime);
   }

   template<typename recv_handler>
   void expect_recv(std::string const &expectedInboundMessage, recv_handler &&recvHandler)
   {
      EXPECT_CALL(*this, io_frame_received(testing::_, testing::_))
         .WillOnce(
            [expectedInboundMessage, recvHandler] (auto const &dataFrame, auto const finalFrame)
            {
               EXPECT_EQ(websocket_frame_type::text, dataFrame.type);
               EXPECT_TRUE(finalFrame);
               std::string_view const inboundMessage
               {
                  std::bit_cast<char const *>(dataFrame.bytes),
                  dataFrame.bytesLength,
               };
               EXPECT_EQ(expectedInboundMessage, inboundMessage);
               recvHandler();
               return std::error_code{};
            }
         )
      ;
   }

   [[nodiscard]] auto wait_for(time_duration const timeout) const
   {
      assert(nullptr != m_internalState);
      return m_internalState->doneFuture.wait_for(timeout);
   }

private:
   std::unique_ptr<internal_state> m_internalState{nullptr,};
   std::string m_lastOutboundMessage{"",};
   std::atomic_bool m_connected{false,};

   void io_connected() final
   {
      super::io_connected();
      m_connected.store(true, std::memory_order_relaxed);
   }

   MOCK_METHOD(std::error_code, io_frame_received, (websocket_frame const &, bool), (final));
   MOCK_METHOD(websocket_frame, io_frame_to_send, (), (final));
   MOCK_METHOD(void, io_disconnected, (std::error_code const &), (final));
   MOCK_METHOD(tcp_client_config, io_ready_to_connect, (), (final));
   MOCK_METHOD(websocket_client_config, io_ready_to_handshake, (), (final));
};

using test_wss_client = testing::StrictMock<wss_client_mock>;

using wss_client = testsuite;

}

TEST_F(wss_client, connect_timeout)
{
   constexpr size_t testSocketListCapacity{1,};
   constexpr size_t testIoBufferCapacity{1,};
   tcp_client_thread const testThread{tcp_client_thread_config{testSocketListCapacity, testIoBufferCapacity,},};
   x509_store const testX509Store{x509_store_config{},};
   constexpr size_t testTlsSessionListCapacity{testSocketListCapacity,};
   tls_client_context const testTlsContext{testThread, testX509Store, test_domain, testTlsSessionListCapacity,};
   constexpr size_t testWssSessionListCapacity{testTlsSessionListCapacity,};
   constexpr size_t testWssBufferCatacity{1,};
   wss_client_context const testWebsocketContext{testTlsContext, testWssSessionListCapacity, testWssBufferCatacity,};
   test_wss_client testClient{testWebsocketContext,};
   constexpr uint16_t testPort{444,};
   test_tcp_connect_timeout(testClient, testPort);
}

TEST_F(wss_client, wss)
{
   constexpr size_t testSocketListCapacity{1,};
   constexpr size_t testIoBufferCapacity{4 * 1024,};
   tcp_client_thread const testThread{tcp_client_thread_config{testSocketListCapacity, testIoBufferCapacity,},};
#if (defined(IO_THREADS_OPENSSL))
   x509_store const testX509Store{test_certificate_pem(), x509_format::pem,};
#elif (defined(IO_THREADS_SCHANNEL))
   x509_store const testX509Store{test_certificate_p12(), x509_format::p12,};
#endif
   constexpr size_t testTlsSessionListCapacity{testSocketListCapacity,};
   tls_client_context const testTlsContext{testThread, testX509Store, test_domain, testTlsSessionListCapacity,};
   constexpr size_t testWssSessionListCapacity{testTlsSessionListCapacity,};
   constexpr size_t testWssBufferCatacity{256,};
   wss_client_context const testWebsocketContext{testTlsContext, testWssSessionListCapacity, testWssBufferCatacity,};
   test_wss_client testClient{testWebsocketContext,};
   test_websocket_client<boost::beast::websocket::stream<test_tls_stream, true>>(testClient);
}

namespace
{

class ping_client_mock : public io_threads::wss_client
{
private:
   using super = io_threads::wss_client;

   struct internal_state final
   {
      std::promise<void> done{};
      std::future<void> doneFuture{done.get_future(),};
   };

public:
   static constexpr std::chrono::milliseconds connect_timeout{10,};

   using super::super;

   ping_client_mock &operator = (ping_client_mock &&) = delete;
   ping_client_mock &operator = (ping_client_mock const &) = delete;

   void start(tcp_client_config const &tcpConfig, websocket_client_config const &websocketConfig, time_duration const pingTimeout, system_time const connectTime)
   {
      m_pingTimeout = pingTimeout;
      m_sentPing = 0;
      m_recvedPing = 0;
      wait_for_pong();
      EXPECT_CALL(*this, io_frame_to_send())
         .WillOnce(
            [this, connectTime] ()
            {
               EXPECT_GT(system_clock::now(), connectTime);
               schedule_ping();
               return websocket_frame{};
            }
         )
      ;
      ready_to_send();
      EXPECT_CALL(*this, io_ready_to_handshake()).WillOnce(testing::Return(websocketConfig));
      m_internalState = std::make_unique<internal_state>();
      EXPECT_CALL(*this, io_ready_to_connect()).WillOnce(testing::Return(tcpConfig));
      ready_to_connect_deferred(connectTime);
   }

   [[nodiscard]] auto wait_for(time_duration const timeout) const
   {
      assert(nullptr != m_internalState);
      return std::make_tuple(m_internalState->doneFuture.wait_for(timeout), m_recvedPing, expected_number_of_pings());
   }

private:
   std::unique_ptr<internal_state> m_internalState{nullptr,};
   std::string m_lastOutboundMessage{"",};
   std::atomic_bool m_connected{false,};
   time_duration m_pingTimeout{time_duration::zero(),};
   size_t m_sentPing{0,};
   size_t m_recvedPing{0,};
   system_time m_nextPingTime{time_duration::zero(),};

   [[nodiscard]] size_t expected_number_of_pings() const noexcept
   {
      return static_cast<size_t>((std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::seconds{1,}) - connect_timeout) / m_pingTimeout - 1);
   }

   void handle_pong(std::string_view const inboundMessage)
   {
      EXPECT_EQ(std::to_string(m_recvedPing), inboundMessage);
      if (expected_number_of_pings() >= m_recvedPing)
      {
         ++m_recvedPing;
         wait_for_pong();
      }
   }

   void io_connected() final
   {
      super::io_connected();
      m_connected.store(true, std::memory_order_relaxed);
   }

   void schedule_ping()
   {
      if (expected_number_of_pings() == m_sentPing)
      {
         return;
      }
      EXPECT_CALL(*this, io_frame_to_send())
         .WillOnce(
            [this] ()
            {
               EXPECT_GE(system_clock::now(), m_nextPingTime);
               EXPECT_CALL(*this, io_frame_to_send()).WillRepeatedly(
                  [this] ()
                  {
                     EXPECT_CALL(*this, io_frame_to_send()).Times(0);
                     schedule_ping();
                     return websocket_frame{};
                  }
               );
               m_lastOutboundMessage = std::to_string(m_sentPing);
               ++m_sentPing;
               return websocket_frame
               {
                  .bytes = std::bit_cast<std::byte *>(m_lastOutboundMessage.data()),
                  .bytesLength = m_lastOutboundMessage.size(),
                  .type = websocket_frame_type::text,
               };
            }
         )
      ;
      m_nextPingTime = system_clock::now() + m_pingTimeout;
      ready_to_send_deferred(m_nextPingTime);
   }

   void wait_for_pong()
   {
      if (expected_number_of_pings() == m_recvedPing)
      {
         assert(m_sentPing == m_recvedPing);
         EXPECT_CALL(*this, io_disconnected(testing::_))
            .WillOnce(
               [this] (auto const errorCode)
               {
                  m_lastOutboundMessage.clear();
                  m_connected.store(false, std::memory_order_relaxed);
                  super::io_disconnected(errorCode);
                  EXPECT_FALSE(errorCode) << errorCode.value() << ": " << errorCode.message();
                  EXPECT_CALL(*this, io_frame_received(testing::_, testing::_)).Times(0);
                  EXPECT_CALL(*this, io_frame_to_send()).Times(0);
                  EXPECT_CALL(*this, io_disconnected(testing::_)).Times(0);
                  EXPECT_CALL(*this, io_ready_to_connect()).Times(0);
                  EXPECT_CALL(*this, io_ready_to_handshake()).Times(0);
                  assert(nullptr != m_internalState);
                  m_internalState->done.set_value();
               }
            )
         ;
         ready_to_close(websocket_closure_reason::normal);
         return;
      }
      EXPECT_CALL(*this, io_frame_received(testing::_, testing::_))
         .WillOnce(
            [this] (auto const &dataFrame, auto const finalFrame)
            {
               EXPECT_EQ(websocket_frame_type::text, dataFrame.type);
               EXPECT_TRUE(finalFrame);
               std::string_view const inboundMessage
               {
                  std::bit_cast<char const *>(dataFrame.bytes),
                  dataFrame.bytesLength,
               };
               handle_pong(inboundMessage);
               return std::error_code{};
            }
         )
      ;
   }

   MOCK_METHOD(std::error_code, io_frame_received, (websocket_frame const &, bool), (final));
   MOCK_METHOD(websocket_frame, io_frame_to_send, (), (final));
   MOCK_METHOD(void, io_disconnected, (std::error_code const &), (final));
   MOCK_METHOD(tcp_client_config, io_ready_to_connect, (), (final));
   MOCK_METHOD(websocket_client_config, io_ready_to_handshake, (), (final));
};

using test_ping_client = testing::StrictMock<ping_client_mock>;

}

TEST_F(wss_client, ping_pong)
{
   system_network_interfaces testNetworkInterfaces{};
   auto const &testLoopbackNetworkInterface{testNetworkInterfaces.loopback(),};
   ASSERT_TRUE(testLoopbackNetworkInterface.has_value());
   auto testNetworkInterfaceIps = std::vector<std::string_view>{};
   if (true == testLoopbackNetworkInterface.value().ipv4().has_value())
   {
      std::string_view const testNetworkInterfaceIp{testLoopbackNetworkInterface->ipv4().value(),};
      ASSERT_FALSE(testNetworkInterfaceIp.empty());
      testNetworkInterfaceIps.push_back(testNetworkInterfaceIp);
   }
   if (true == testLoopbackNetworkInterface.value().ipv6().has_value())
   {
      std::string_view const testNetworkInterfaceIp{testLoopbackNetworkInterface->ipv6().value(),};
      ASSERT_FALSE(testNetworkInterfaceIp.empty());
      testNetworkInterfaceIps.push_back(testNetworkInterfaceIp);
   }
   ASSERT_FALSE(testNetworkInterfaceIps.empty());
   constexpr std::chrono::seconds testTimeout{5,};
   constexpr tcp_keep_alive testTcpKeepAlive
   {
      .idleTimeout = testTimeout,
      .probeTimeout = testTimeout,
      .probesCount = 0,
   };
   constexpr auto testHeartbeatTimeouts{std::to_array({11, 13, 17, 19, 23, 29, 31, 37, 41, 43,}),};
   constexpr auto testSocketListCapacity{testHeartbeatTimeouts.size(),};
   constexpr size_t testIoBufferCapacity{4 * 1024,};
   tcp_client_thread const testThread{tcp_client_thread_config{testSocketListCapacity, testIoBufferCapacity,},};
#if (defined(IO_THREADS_OPENSSL))
   x509_store const testX509Store{test_certificate_pem(), x509_format::pem,};
#elif (defined(IO_THREADS_SCHANNEL))
   x509_store const testX509Store{test_certificate_p12(), x509_format::p12,};
#endif
   constexpr size_t testTlsSessionListCapacity{testSocketListCapacity,};
   tls_client_context const testTlsContext{testThread, testX509Store, test_domain, testTlsSessionListCapacity,};
   constexpr size_t testWssSessionListCapacity{testTlsSessionListCapacity,};
   constexpr size_t testWssBufferCatacity{256,};
   wss_client_context const testWebsocketContext{testTlsContext, testWssSessionListCapacity, testWssBufferCatacity,};
   std::array<std::unique_ptr<test_ping_client>, testWssSessionListCapacity> testClients{};
   for (auto &testClient : testClients)
   {
      testClient = std::make_unique<test_ping_client>(testWebsocketContext);
   }
   constexpr std::chrono::milliseconds testConnectTimeout{10,};
   for (auto const &testPeerHost : testNetworkInterfaceIps)
   {
      testing::StrictMock<test_websocket_server<boost::beast::websocket::stream<test_tls_stream, true>>> testServer{boost::asio::ip::make_address(testPeerHost),};
      EXPECT_CALL(testServer, should_accept_socket()).WillRepeatedly(testing::Return(true));
      EXPECT_CALL(testServer, should_pass_handshake()).WillRepeatedly(testing::Return(true));
      EXPECT_CALL(testServer, should_accept_websocket()).WillRepeatedly(testing::Return(true));
      EXPECT_CALL(testServer, handle_message(testing::_, testing::_))
         .WillRepeatedly(
            [] (auto const &testInboundBuffer, auto &testOutboundBuffer)
            {
               std::string_view const testInboundMessage
               {
                  static_cast<char const *>(testInboundBuffer.data().data()),
                  testInboundBuffer.data().size(),
               };
               testOutboundBuffer.append(testInboundMessage);
               return true;
            }
         )
      ;
      EXPECT_CALL(testServer, should_keep_alive()).WillRepeatedly(testing::Return(true));
      std::error_code testErrorCode{};
      auto const testSocketAddress{make_socket_address(testPeerHost, testServer.local_port(), testErrorCode),};
      ASSERT_FALSE(testErrorCode) << testErrorCode.value() << ": " << testErrorCode.message();
      ASSERT_TRUE(testSocketAddress.has_value());
      auto const testTcpConfig
      {
         tcp_client_config{tcp_client_address{testLoopbackNetworkInterface.value(), testSocketAddress.value()}}
            .with_keep_alive(testTcpKeepAlive)
            .with_nodelay()
            .with_user_timeout(testTimeout)
         ,
      };
      websocket_client_config const testWebsocketConfig{"/test?name=ping_pong",};
      auto const testConnectTime{system_clock::now() + testConnectTimeout,};
      for (size_t testIndex{0,}; testWssSessionListCapacity > testIndex; ++testIndex)
      {
         testClients[testIndex]->start(testTcpConfig, testWebsocketConfig, std::chrono::milliseconds{testHeartbeatTimeouts[testIndex],}, testConnectTime);
      }
      std::array<std::future_status, testWssSessionListCapacity> testFutureStatuses{};
      std::array<size_t, testWssSessionListCapacity> testResults{};
      std::array<size_t, testWssSessionListCapacity> expectedResults{};
      for (size_t testIndex{0,}; testWssSessionListCapacity > testIndex; ++testIndex)
      {
         auto const [testFutureStatus, testResult, expectedResult]{testClients[testIndex]->wait_for(testTimeout)};
         testFutureStatuses[testIndex] = testFutureStatus;
         testResults[testIndex] = testResult;
         expectedResults[testIndex] = expectedResult;
      }
      ASSERT_THAT(testFutureStatuses, testing::Each(std::future_status::ready));
      ASSERT_THAT(testResults, testing::ElementsAreArray(expectedResults));
   }
}

}
