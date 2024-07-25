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

#include "string_view_serializer.mock.hpp"
#include "testsuite.hpp"

#include <gmock/gmock.h>
#include <io_threads/file_writer_thread.hpp>
#include <io_threads/rotating_file_write_queue.hpp>

#include <deque>
#include <format>
#include <fstream>
#include <future>

namespace io_threads::tests
{

namespace internals
{

class rotating_file_write_queue_mock : public rotating_file_write_queue<std::string_view, test_string_view_serializer_mock>
{
private:
   using super = rotating_file_write_queue<std::string_view, test_string_view_serializer_mock>;

   struct internal_state final
   {
      std::promise<void> done = {};
      std::future<void> doneFuture = done.get_future();
   };

public:
   using super::super;

   rotating_file_write_queue_mock &operator = (rotating_file_write_queue_mock &&) = delete;
   rotating_file_write_queue_mock &operator = (rotating_file_write_queue_mock const &) = delete;

   void expect_close()
   {
      expect_error(std::error_code{});
      stop();
   }

   template<typename error_code_matcher>
   void expect_error(error_code_matcher &&errorCodeMatcher)
   {
      EXPECT_CALL(*this, io_queue_stopped(testing::_))
         .WillOnce(
            [this, errorCodeMatcher] (auto const errorCode)
            {
               EXPECT_THAT(errorCode, errorCodeMatcher) << errorCode.value() << ": " << errorCode.message();
               EXPECT_CALL(*this, get_timestamp(testing::_)).Times(0);
               EXPECT_CALL(*this, io_queue_started()).Times(0);
               EXPECT_CALL(*this, io_queue_stopped(testing::_)).Times(0);
               EXPECT_CALL(*this, make_config(testing::_)).Times(0);
               assert(nullptr != m_internalState);
               m_internalState->done.set_value();
            }
         )
      ;
   }

   void expect_get_timestamp(timestamp_type const timestamp)
   {
      EXPECT_CALL(*this, get_timestamp(testing::_)).WillOnce(testing::Return(timestamp));
   }

   void expect_first_file(timestamp_type const timestamp, file_writer_config const &testConfig)
   {
      m_internalState = std::make_unique<internal_state>();
      EXPECT_CALL(*this, io_queue_started()).Times(1);
      EXPECT_CALL(*this, make_config(timestamp)).WillOnce(testing::Return(testConfig));
   }

   void expect_next_file(timestamp_type const timestamp, file_writer_config const &testConfig)
   {
      EXPECT_CALL(*this, make_config(timestamp)).WillOnce(testing::Return(testConfig));
   }

   [[nodiscard]] auto wait_for(std::chrono::seconds const timeout) const
   {
      assert(nullptr != m_internalState);
      return m_internalState->doneFuture.wait_for(timeout);
   }

private:
   std::unique_ptr<internal_state> m_internalState{nullptr,};

   MOCK_METHOD(timestamp_type, get_timestamp, (std::string_view const &), (final));
   MOCK_METHOD(void, io_queue_started, (), (final));
   MOCK_METHOD(void, io_queue_stopped, (std::error_code const &), (final));
   MOCK_METHOD(file_writer_config, make_config, (timestamp_type), (final));
};

}

namespace
{

using rotating_file_write_queue_mock = testing::StrictMock<internals::rotating_file_write_queue_mock>;

using file_writer = testsuite;

}

TEST_F(file_writer, rotating_file_write_queue)
{
   auto const testDirectory = std::filesystem::temp_directory_path() / std::string{"io_thread_test_"}.append(random_string(10));
   std::filesystem::remove_all(testDirectory);
   std::filesystem::create_directories(testDirectory);
   {
      constexpr size_t testFileListCapacity{1,};
      constexpr size_t testIoBufferCapacity{2 * 1024,}; ///< 2 KiB
      file_writer_thread const testFileWriterThread{file_writer_thread_config{testFileListCapacity, testIoBufferCapacity,},};
      rotating_file_write_queue_mock testFileWriterQueue{testFileWriterThread,};
      constexpr size_t testMinStringLength = 1024; ///< 1 KiB
      constexpr size_t testMaxStringLength = 5 * 1024; ///< 5 KiB
      auto const testFormatFileName = [] (rotating_file_write_queue_mock::timestamp_type const timestamp) -> std::string
      {
         constexpr std::string_view testFilenameFormat{"{:%F}.test",};
         return std::vformat(testFilenameFormat, std::make_format_args(timestamp));
      };
      rotating_file_write_queue_mock::timestamp_type testInitialTimestamp{std::chrono::floor<std::chrono::days>(std::chrono::system_clock::now()),};
      testFileWriterQueue.expect_first_file(
         testInitialTimestamp,
         file_writer_config{testDirectory / testFormatFileName(testInitialTimestamp), file_writer_option::create_new,}
      );
      std::deque<std::string> testDataCunks{};
      auto testPrevTimestamp{testInitialTimestamp,};
      auto testNextTimestamp{testInitialTimestamp,};
      auto const testGenerateNextDataChunk = [&] () -> std::string const &
      {
         auto testDataChunk{random_string(testMinStringLength, testMaxStringLength),};
         auto const testPrevDay{std::chrono::floor<std::chrono::days>(testPrevTimestamp),};
         auto const testNextDay{std::chrono::floor<std::chrono::days>(testNextTimestamp),};
         if (testPrevDay < testNextDay)
         {
            testFileWriterQueue.expect_next_file(
               testNextTimestamp,
               file_writer_config{testDirectory / testFormatFileName(testNextTimestamp), file_writer_option::create_new,}
            );
         }
         testFileWriterQueue.expect_get_timestamp(testNextTimestamp);
         testPrevTimestamp = testNextTimestamp;
         testNextTimestamp += std::chrono::minutes{10,};
         return testDataCunks.emplace_back(std::move(testDataChunk));
      };
      constexpr size_t testDaysCount{3,};
      constexpr size_t testMessagesPerDay{143,};
      for (size_t testIteration{0}; (testDaysCount * testMessagesPerDay) > testIteration; ++testIteration)
      {
         testFileWriterQueue.push(testGenerateNextDataChunk());
      }
      testFileWriterQueue.expect_close();
      EXPECT_EQ(std::future_status::ready, testFileWriterQueue.wait_for(std::chrono::minutes{1,}));
      std::string testDataChunk;
      for (size_t testIndex{0,}; testDaysCount > testIndex; ++testIndex)
      {
         std::ifstream testFile
         {
            testDirectory / testFormatFileName(testInitialTimestamp + std::chrono::days{1,} * testIndex),
            std::ios::binary | std::ios::in
         };
         while (false == testDataCunks.empty())
         {
            testDataChunk.resize(testDataCunks.front().size());
            if (false == testFile.read(testDataChunk.data(), testDataChunk.size()).eof())
            {
               EXPECT_EQ(testDataCunks.front(), testDataChunk);
               testDataCunks.pop_front();
            }
            else
            {
               break;
            }
         }
         testFile.close();
      }
   }
   std::filesystem::remove_all(testDirectory);
}

}
