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

#include "tcp/test_tcp_connect_timeout.hpp"
#include "tcp/rest/test_rest_client.hpp"
#include "testsuite.hpp"

#include <io_threads/tcp_client.hpp>

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
      std::promise<void> done{};
      std::future<void> doneFuture{done.get_future(),};
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
   void expect_error(error_code_matcher errorCodeMatcher)
   {
      executor().execute(
         [this, errorCodeMatcher = std::move(errorCodeMatcher)] ()
         {
            EXPECT_CALL(*this, io_disconnected(testing::_))
               .WillOnce(
                  [this, errorCodeMatcher = std::move(errorCodeMatcher)] (auto const errorCode)
                  {
                     EXPECT_THAT(errorCode, errorCodeMatcher) << errorCode.value() << ": " << errorCode.message();
                     EXPECT_CALL(*this, io_data_received(testing::_, testing::_)).Times(0);
                     EXPECT_CALL(*this, io_data_to_send(testing::_, testing::_)).Times(0);
                     EXPECT_CALL(*this, io_disconnected(testing::_)).Times(0);
                     EXPECT_CALL(*this, io_ready_to_connect()).Times(0);
                     if (nullptr != m_internalState)
                     {
                        m_connected.store(false, std::memory_order_relaxed);
                        m_internalState->done.set_value();
                     }
                     else
                     {
                        EXPECT_FALSE(m_connected.load(std::memory_order_relaxed));
                     }
                  }
               )
            ;
         }
      );
   }

   void expect_ready_to_connect(tcp_client_config testConfig)
   {
      m_internalState = std::make_unique<internal_state>();
      executor().execute(
         [this, testConfig = std::move(testConfig)] ()
         {
            EXPECT_CALL(*this, io_ready_to_connect()).WillOnce(testing::Return(std::move(testConfig)));
         }
      );
      ready_to_connect();
   }

   void expect_ready_to_connect_deferred(steady_time const testNotBeforeTime)
   {
      m_internalState = std::make_unique<internal_state>();
      ready_to_connect_deferred(testNotBeforeTime);
   }

   void expect_ready_to_connect_deferred(tcp_client_config testConfig, steady_time const testNotBeforeTime)
   {
      m_internalState = std::make_unique<internal_state>();
      executor().execute(
         [this, testConfig = std::move(testConfig)] ()
         {
            EXPECT_CALL(*this, io_ready_to_connect()).WillOnce(testing::Return(std::move(testConfig)));
         }
      );
      ready_to_connect_deferred(testNotBeforeTime);
   }

   void expect_ready_to_send(std::string message)
   {
      executor().execute(
         [this, message = std::move(message)] ()
         {
            EXPECT_CALL(*this, io_data_to_send(testing::_, testing::_))
               .WillOnce(
                  [this, message = std::move(message)] (auto const &dataChunk, auto &bytesWritten)
                  {
                     EXPECT_CALL(*this, io_data_to_send(testing::_, testing::_)).WillRepeatedly(
                        [this] (auto const &, auto &bytesWritten)
                        {
                           bytesWritten = 0;
                           EXPECT_CALL(*this, io_data_to_send(testing::_, testing::_)).Times(0);
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
         }
      );
      ready_to_send();
   }

   void expect_ready_to_send(std::function<void()> sendHandler)
   {
      ASSERT_TRUE(sendHandler);
      executor().execute(
         [this, sendHandler = std::move(sendHandler)] ()
         {
            EXPECT_CALL(*this, io_data_to_send(testing::_, testing::_))
               .WillOnce(
                  [sendHandler = std::move(sendHandler)] (auto const &, auto &bytesWritten)
                  {
                     sendHandler();
                     bytesWritten = 0;
                     return std::error_code{};
                  }
               )
            ;
         }
      );
      ready_to_send();
   }

   void expect_ready_to_send_deferred(steady_time const testNotBeforeTime)
   {
      ready_to_send_deferred(testNotBeforeTime);
   }

   void expect_ready_to_send_deferred(std::string message, steady_time const testNotBeforeTime)
   {
      executor().execute(
         [this, message = std::move(message)] ()
         {
            EXPECT_CALL(*this, io_data_to_send(testing::_, testing::_))
               .WillOnce(
                  [this, message = std::move(message)] (auto const &dataChunk, auto &bytesWritten)
                  {
                     EXPECT_CALL(*this, io_data_to_send(testing::_, testing::_)).WillRepeatedly(
                        [this] (auto const &, auto &bytesWritten)
                        {
                           bytesWritten = 0;
                           EXPECT_CALL(*this, io_data_to_send(testing::_, testing::_)).Times(0);
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
         }
      );
      ready_to_send_deferred(testNotBeforeTime);
   }

   template<typename recv_handler>
   void expect_recv(std::string expectedMessage, recv_handler recvHandler)
   {
      executor().execute(
         [this, expectedMessage = std::move(expectedMessage), recvHandler = std::move(recvHandler)] ()
         {
            EXPECT_CALL(*this, io_data_received(testing::_, testing::_))
               .WillOnce(
                  [expectedMessage = std::move(expectedMessage), recvHandler = std::move(recvHandler)] (auto const &dataChunk, auto &bytesRead)
                  {
                     std::string_view const receivedMessage
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
      );
   }

   [[nodiscard]] auto wait_for(time_duration const timeout) const
   {
      assert(nullptr != m_internalState);
      return m_internalState->doneFuture.wait_for(timeout);
   }

private:
   std::unique_ptr<internal_state> m_internalState{nullptr,};
   std::atomic_bool m_connected{false,};

   void io_connected() final
   {
      m_connected.store(true, std::memory_order_relaxed);
   }

   MOCK_METHOD(std::error_code, io_data_to_send, (data_chunk const &, size_t &), (final));
   MOCK_METHOD(std::error_code, io_data_received, (data_chunk const &, size_t &), (final));
   MOCK_METHOD(void, io_disconnected, (std::error_code const &), (final));
   MOCK_METHOD(tcp_client_config, io_ready_to_connect, (), (final));

   [[nodiscard]] std::error_code io_data_to_shutdown(data_chunk const &, size_t &bytesWritten) final
   {
      bytesWritten = 0;
      return std::error_code{};
   }
};

using test_tcp_client = testing::StrictMock<tcp_client_mock>;

using tcp_client = testsuite;

}

TEST_F(tcp_client, connect_timeout)
{
   constexpr uint32_t testSocketListCapacity{1,};
   constexpr uint32_t testRecvBufferSize{1,};
   constexpr uint32_t testSendBufferSize{1,};
   tcp_client_thread const testThread{thread_config{}, testSocketListCapacity, testRecvBufferSize, testSendBufferSize,};
   test_tcp_client testClient{testThread,};
   constexpr uint16_t testPort{81,};
   test_tcp_connect_timeout(testClient, testPort);
}

TEST_F(tcp_client, http)
{
   constexpr uint32_t testSocketListCapacity{1,};
   constexpr uint32_t testRecvBufferSize{256,};
   constexpr uint32_t testSendBufferSize{256,};
   tcp_client_thread const testThread{thread_config{}, testSocketListCapacity, testRecvBufferSize, testSendBufferSize,};
   test_tcp_client testClient{testThread,};
   test_rest_client<boost::beast::tcp_stream>(testThread, testClient);
}

}
