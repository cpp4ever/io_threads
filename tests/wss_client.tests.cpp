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
      if (true == m_connected.load(std::memory_order_relaxed))
      {
         ready_to_send();
      }
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
      if (true == m_connected.load(std::memory_order_relaxed))
      {
         ready_to_send();
      }
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

   [[nodiscard]] auto wait_for(std::chrono::seconds const timeout) const
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
   constexpr size_t testTlsSessionListCapacity{1,};
   tls_client_context const testTlsContext{testThread, testX509Store, test_domain, testTlsSessionListCapacity,};
   constexpr size_t tesWssSessionListCapacity{1,};
   constexpr size_t testWssBufferCatacity{1,};
   wss_client_context const testWebsocketContext{testTlsContext, tesWssSessionListCapacity, testWssBufferCatacity,};
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
   constexpr size_t testTlsSessionListCapacity{1,};
   tls_client_context const testTlsContext{testThread, testX509Store, test_domain, testTlsSessionListCapacity,};
   constexpr size_t tesWssSessionListCapacity{1,};
   constexpr size_t testWssBufferCatacity{256,};
   wss_client_context const testWebsocketContext{testTlsContext, tesWssSessionListCapacity, testWssBufferCatacity,};
   test_wss_client testClient{testWebsocketContext,};
   test_websocket_client<boost::beast::websocket::stream<test_tls_stream, true>>(testClient);
}

}
