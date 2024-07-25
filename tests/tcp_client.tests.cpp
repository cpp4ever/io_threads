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

#include "tcp/test_tcp_common.hpp" ///< for test_keep_alive_delay, test_loopback_interface, test_loopback_ip, test_peer_port
#include "tcp/rest/test_rest_client.hpp" ///< for test_rest_client, test_rest_client_traits
#include "testsuite.hpp"

#include <boost/beast.hpp> ///< for boost::beast::tcp_stream
#include <gmock/gmock.h> ///< for EXPECT_CALL, MOCK_METHOD, testing::Return, testing::StrictMock, testing::_
#include <gtest/gtest.h> ///< for TEST
#include <io_threads/tcp_client.hpp> ///< for io_threads::tcp_client

#include <cstdint> ///< for uint16_t
#include <string_view> ///< for std::string_view

namespace io_threads::tests
{

class tcp_client_mock : public tcp_client
{
private:
   struct internal_state final
   {
      std::atomic_bool asleep = false;
      std::promise<void> done = {};
      std::future<void> doneFuture = done.get_future();
   };

public:
   using tcp_client::tcp_client;

   tcp_client_mock &operator = (tcp_client_mock &&) = delete;
   tcp_client_mock &operator = (tcp_client_mock const &) = delete;

   void expect_disconnect()
   {
      expect_error(testing::AnyOf(std::error_code{}));
      ready_to_disconnect();
   }

   template<typename error_code_matcher>
   void expect_error(error_code_matcher &&errorCodeMatcher)
   {
      EXPECT_CALL(*this, io_disconnected(testing::_))
         .WillOnce(
            [this, errorCodeMatcher] (auto const errorCode)
            {
               EXPECT_THAT(errorCode, errorCodeMatcher) << errorCode.value() << ": " << errorCode.message();
               EXPECT_CALL(*this, io_data_received(testing::_, testing::_)).Times(0);
               EXPECT_CALL(*this, io_data_to_send(testing::_, testing::_)).Times(0);
               EXPECT_CALL(*this, io_disconnected(testing::_)).Times(0);
               EXPECT_CALL(*this, io_ready_to_connect()).Times(0);
               assert(nullptr != m_internalState);
               m_internalState->asleep.store(false, std::memory_order_relaxed);
               m_internalState->done.set_value();
            }
         )
      ;
   }

   template<typename error_code_matcher>
   void expect_error_on_send(std::string const &message, error_code_matcher &&errorCodeMatcher)
   {
      EXPECT_CALL(*this, io_data_to_send(testing::_, testing::_))
         .WillOnce(
            [this, message, errorCodeMatcher] (auto *bytes, auto const bytesLength)
            {
               EXPECT_CALL(*this, io_data_to_send(testing::_, testing::_)).WillRepeatedly(
                  [this] (auto *, auto)
                  {
                     EXPECT_CALL(*this, io_data_to_send(testing::_, testing::_)).Times(0);
                     assert(nullptr != m_internalState);
                     m_internalState->asleep.store(true, std::memory_order_release);
                     return 0;
                  }
               );
               expect_error(errorCodeMatcher);
               assert(message.size() <= bytesLength);
               std::memcpy(bytes, message.data(), message.size());
               return message.size();
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

   void expect_ready_to_connect(tcp_client_config const &testConfig)
   {
      m_internalState = std::make_unique<internal_state>();
      EXPECT_CALL(*this, io_ready_to_connect()).WillOnce(testing::Return(testConfig));
      ready_to_connect();
   }

   void expect_ready_to_send(std::string const &message)
   {
      EXPECT_CALL(*this, io_data_to_send(testing::_, testing::_))
         .WillOnce(
            [this, message] (auto *bytes, auto const bytesLength)
            {
               EXPECT_CALL(*this, io_data_to_send(testing::_, testing::_)).WillOnce(
                  [this] (auto *, auto)
                  {
                     assert(nullptr != m_internalState);
                     m_internalState->asleep.store(true, std::memory_order_release);
                     return 0;
                  }
               );
               assert(message.size() <= bytesLength);
               std::memcpy(bytes, message.data(), message.size());
               return message.size();
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
   void expect_recv(std::string const &message, recv_handler &&recvHandler)
   {
      m_receivedMessage.clear();
      m_receivedMessage.reserve(message.size() + 1);
      EXPECT_CALL(*this, io_data_received(testing::_, testing::_))
         .WillOnce(
            [this, message, recvHandler] (auto const *bytes, auto const bytesLength) -> size_t
            {
               m_receivedMessage.append(
                  std::bit_cast<char const *>(bytes),
                  std::min(bytesLength, message.size() - m_receivedMessage.size())
               );
               if (m_receivedMessage.size() < message.size())
               {
                  return 0;
               }
               assert(m_receivedMessage.size() == message.size());
               EXPECT_EQ(m_receivedMessage, message);
               recvHandler();
               return message.size();
            }
         )
      ;
   }

   auto wait_for(std::chrono::seconds const timeout) const
   {
      assert(nullptr != m_internalState);
      return m_internalState->doneFuture.wait_for(timeout);
   }

private:
   std::string m_receivedMessage = {};
   std::unique_ptr<internal_state> m_internalState = {};

   MOCK_METHOD(size_t, io_data_to_send, (std::byte *bytes, size_t bytesCapacity), (final));
   MOCK_METHOD(size_t, io_data_received, (std::byte const *bytes, size_t bytesLength), (final));
   MOCK_METHOD(void, io_disconnected, (std::error_code errorCode), (final));
   MOCK_METHOD(tcp_client_config, io_ready_to_connect, (), (final));

   void io_connected() final
   {
      /// Do nothing
   }

   size_t io_data_to_shutdown(std::byte *, size_t) final
   {
      /// Do nothing
      return 0;
   }
};

using test_tcp_client = testing::StrictMock<tcp_client_mock>;

using tcp_client_thread = testsuite;

TEST(tcp_client_thread, tcp_client)
{
   constexpr size_t testConnectionsCapacity = 0;
   constexpr size_t testRecvBufferSize = 256;
   constexpr size_t testSendBufferSize = 256;
   auto const testThread = io_threads::tcp_client_thread{test_cpu_id, testConnectionsCapacity, testRecvBufferSize, testSendBufferSize};
   auto testClient = test_tcp_client{testThread};
   test_rest_client<boost::beast::tcp_stream>(testClient, test_peer_port);
}

}
