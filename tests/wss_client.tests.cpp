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
#include "tcp/test_tcp_connect_timeout.hpp" ///< for io_threads::tests::test_tcp_connect_timeout
#include "tcp/test_tcp_server_context.hpp" ///< for io_threads::tests::test_tls_stream
#include "tcp/websocket/test_websocket_client.hpp" ///< for test_websocket_client
#include "testsuite.hpp"

#include <io_threads/wss_client.hpp> ///< for io_threads::wss_client

#include <atomic> ///< for std::atomic_bool, std::memory_order_acq_rel, std::memory_order_relaxed, std::memory_order_release
#include <future> ///< for std::future, std::promise

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
      std::string lastOutboundMessage = {};
      std::atomic_bool asleep = false;
      std::promise<void> done = {};
      std::future<void> doneFuture = done.get_future();
   };

public:
   using super::super;

   wss_client_mock &operator = (wss_client_mock &&) = delete;
   wss_client_mock &operator = (wss_client_mock const &) = delete;

   void expect_disconnect()
   {
      expect_error(std::error_code{});
      ready_to_disconnect();
   }

   template<typename error_code_matcher>
   void expect_error(error_code_matcher &&errorCodeMatcher)
   {
      EXPECT_CALL(*this, io_disconnected(testing::_))
         .WillOnce(
            [this, errorCodeMatcher] (auto const errorCode)
            {
               super::io_disconnected(errorCode);
               EXPECT_THAT(errorCode, errorCodeMatcher) << errorCode.value() << ": " << errorCode.message();
               EXPECT_CALL(*this, io_frame_received(testing::_)).Times(0);
               EXPECT_CALL(*this, io_frame_to_send()).Times(0);
               EXPECT_CALL(*this, io_disconnected(testing::_)).Times(0);
               EXPECT_CALL(*this, io_ready_to_connect()).Times(0);
               assert(nullptr != m_internalState);
               m_internalState->asleep.store(false, std::memory_order_relaxed);
               m_internalState->done.set_value();
            }
         )
      ;
   }

   void expect_ready_to_connect(tcp_client_config const &testConfig)
   {
      m_internalState = std::make_unique<internal_state>();
      EXPECT_CALL(*this, io_ready_to_connect()).WillOnce(testing::Return(testConfig));
      ready_to_connect();
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
                     assert(nullptr != m_internalState);
                     m_internalState->asleep.store(true, std::memory_order_release);
                     return websocket_frame{};
                  }
               );
               m_internalState->lastOutboundMessage = outboundMssage;
               return websocket_frame
               {
                  .bytes = std::bit_cast<std::byte *>(m_internalState->lastOutboundMessage.data()),
                  .bytesLength = m_internalState->lastOutboundMessage.size(),
                  .type = websocket_frame_type::text,
                  .final = true,
               };
            }
         )
      ;
      if (
         (nullptr != m_internalState) &&
         (true == m_internalState->asleep.exchange(false, std::memory_order_acq_rel))
      )
      {
         ready_to_send();
      }
   }

   template<typename recv_handler>
   void expect_recv(std::string const &expectedInboundMessage, recv_handler &&recvHandler)
   {
      EXPECT_CALL(*this, io_frame_received(testing::_))
         .WillOnce(
            [expectedInboundMessage, recvHandler] (auto const websocketFrame)
            {
               EXPECT_EQ(websocket_frame_type::text, websocketFrame.type);
               EXPECT_TRUE(websocketFrame.final);
               auto const inboundMessage = std::string_view
               {
                  std::bit_cast<char const *>(websocketFrame.bytes),
                  websocketFrame.bytesLength,
               };
               EXPECT_EQ(expectedInboundMessage, inboundMessage);
               recvHandler();
               return std::error_code{};
            }
         )
      ;
   }

   [[nodiscard]] auto wait_for(std::chrono::seconds const timeout) const
   {
      assert(nullptr != m_internalState);
      return m_internalState->doneFuture.wait_for(timeout);
   }

private:
   std::unique_ptr<internal_state> m_internalState = {};

   MOCK_METHOD(std::error_code, io_frame_received, (websocket_frame), (final));
   MOCK_METHOD(websocket_frame, io_frame_to_send, (), (final));
   MOCK_METHOD(void, io_disconnected, (std::error_code), (final));
   MOCK_METHOD(tcp_client_config, io_ready_to_connect, (), (final));
};

using test_wss_client = testing::StrictMock<wss_client_mock>;

using wss_client = testsuite;

}

TEST(wss_client, connect_timeout)
{
   constexpr uint16_t testCpuId = 0;
   constexpr size_t testConnectionsCapacity = 0;
   constexpr size_t testRecvBufferSize = 1;
   constexpr size_t testSendBufferSize = 1;
   auto const testThread = io_threads::tcp_client_thread
   {
      testCpuId,
      testConnectionsCapacity,
      testRecvBufferSize,
      testSendBufferSize
   };
   constexpr size_t testTlsSessionsCapacity = 0;
   auto testTlsContext = tls_client_context{test_domain, testTlsSessionsCapacity};
   constexpr size_t testInboundBufferListCapacity = 0;
   constexpr size_t testInboundBufferCapacity = 1;
   constexpr size_t testOutboundBufferListCapacity = 0;
   constexpr size_t testOutboundBufferCapacity = 1;
   auto testWebsocketContext = websocket_client_context{
      testInboundBufferListCapacity,
      testInboundBufferCapacity,
      testOutboundBufferListCapacity,
      testOutboundBufferCapacity
   };
   auto testClient = test_wss_client{testThread, testTlsContext, testWebsocketContext};
   constexpr uint16_t testPort = 444;
   test_tcp_connect_timeout(testClient, testPort);
}

TEST(wss_client, wss)
{
   constexpr uint16_t testCpuId = 0;
   constexpr size_t testConnectionsCapacity = 0;
   constexpr size_t testRecvBufferSize = 4 * 1024;
   constexpr size_t testSendBufferSize = 4 * 1024;
   auto const testThread = io_threads::tcp_client_thread
   {
      testCpuId,
      testConnectionsCapacity,
      testRecvBufferSize,
      testSendBufferSize
   };
   constexpr size_t testTlsSessionsCapacity = 1;
   auto testTlsContext = tls_client_context
   {
      test_domain,
      ssl_certificate{test_certificate_p12(), ssl_certificate_type::p12},
      testTlsSessionsCapacity,
   };
   constexpr size_t testInboundBufferListCapacity = 1;
   constexpr size_t testInboundBufferCapacity = 256;
   constexpr size_t testOutboundBufferListCapacity = 1;
   constexpr size_t testOutboundBufferCapacity = 256;
   auto testWebsocketContext = websocket_client_context{
      testInboundBufferListCapacity,
      testInboundBufferCapacity,
      testOutboundBufferListCapacity,
      testOutboundBufferCapacity
   };
   auto testClient = test_wss_client{testThread, testTlsContext, testWebsocketContext};
   test_websocket_client<boost::beast::websocket::stream<test_tls_stream, true>>(testClient);
}

}
