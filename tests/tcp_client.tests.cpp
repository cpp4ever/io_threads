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

#include "tcp/test_tcp_connect_timeout.hpp" ///< for io_threads::tests::test_tcp_connect_timeout
#include "tcp/rest/test_rest_client.hpp" ///< for io_threads::tests::test_rest_client
#include "testsuite.hpp" ///< for io_threads::tests::testsuite

#include <boost/beast.hpp> ///< for boost::beast::tcp_stream
#include <gmock/gmock.h> ///< for EXPECT_CALL, MOCK_METHOD, testing::Return, testing::StrictMock, testing::_
#include <gtest/gtest.h> ///< for TEST
#include <io_threads/tcp_client.hpp> ///< for io_threads::tcp_client

#include <cstdint> ///< for uint16_t
#include <string> ///< for std::string
#include <string_view> ///< for std::string_view

namespace io_threads::tests
{

namespace
{

class tcp_client_mock : public io_threads::tcp_client
{
private:
   using super = io_threads::tcp_client;

   struct internal_state final
   {
      std::atomic_bool asleep = false;
      std::promise<void> done = {};
      std::future<void> doneFuture = done.get_future();
   };

public:
   using super::super;

   tcp_client_mock &operator = (tcp_client_mock &&) = delete;
   tcp_client_mock &operator = (tcp_client_mock const &) = delete;

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
            [this, message] (auto const dataChunk, auto &bytesWritten)
            {
               EXPECT_CALL(*this, io_data_to_send(testing::_, testing::_)).WillRepeatedly(
                  [this] (auto const, auto &bytesWritten)
                  {
                     bytesWritten = 0;
                     EXPECT_CALL(*this, io_data_to_send(testing::_, testing::_)).Times(0);
                     assert(nullptr != m_internalState);
                     m_internalState->asleep.store(true, std::memory_order_release);
                     return std::error_code{};
                  }
               );
               assert(message.size() <= dataChunk.bytesLength);
               std::memcpy(dataChunk.bytes, message.data(), message.size());
               bytesWritten = message.size();
               return std::error_code{};
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
   void expect_recv(std::string const &expectedMessage, recv_handler &&recvHandler)
   {
      EXPECT_CALL(*this, io_data_received(testing::_, testing::_))
         .WillOnce(
            [expectedMessage, recvHandler] (auto const dataChunk, auto &bytesRead)
            {
               auto const receivedMessage = std::string_view
               {
                  std::bit_cast<char const *>(dataChunk.bytes),
                  dataChunk.bytesLength,
               };
               EXPECT_EQ(expectedMessage, receivedMessage);
               bytesRead = dataChunk.bytesLength;
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

   MOCK_METHOD(std::error_code, io_data_to_send, (data_chunk, size_t &), (final));
   MOCK_METHOD(std::error_code, io_data_received, (data_chunk, size_t &), (final));
   MOCK_METHOD(void, io_disconnected, (std::error_code), (final));
   MOCK_METHOD(tcp_client_config, io_ready_to_connect, (), (final));

   void io_connected() final
   {
      /// Do nothing
   }

   [[nodiscard]] std::error_code io_data_to_shutdown(data_chunk, size_t &bytesWritten) final
   {
      bytesWritten = 0;
      return {};
   }
};

using test_tcp_client = testing::StrictMock<tcp_client_mock>;

using tcp_client = testsuite;

}

TEST(tcp_client, connect_timeout)
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
   auto testClient = test_tcp_client{testThread};
   constexpr uint16_t testPort = 81;
   test_tcp_connect_timeout(testClient, testPort);
}

TEST(tcp_client, http)
{
   constexpr uint16_t testCpuId = 0;
   constexpr size_t testConnectionsCapacity = 1;
   constexpr size_t testRecvBufferSize = 256;
   constexpr size_t testSendBufferSize = 256;
   auto const testThread = io_threads::tcp_client_thread
   {
      testCpuId,
      testConnectionsCapacity,
      testRecvBufferSize,
      testSendBufferSize
   };
   auto testClient = test_tcp_client{testThread};
   test_rest_client<boost::beast::tcp_stream>(testClient);
}

}
