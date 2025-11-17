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
#include <io_threads/file_write_queue.hpp>
#include <io_threads/file_writer_thread.hpp>

#include <deque>
#include <fstream>
#include <future>

namespace io_threads::tests
{

namespace
{

class file_write_queue_mock : public file_write_queue<std::string_view, test_string_view_serializer_mock>
{
private:
   using super = file_write_queue<std::string_view, test_string_view_serializer_mock>;

   struct internal_state final
   {
      std::promise<void> done = {};
      std::future<void> doneFuture = done.get_future();
   };

public:
   using super::super;

   file_write_queue_mock &operator = (file_write_queue_mock &&) = delete;
   file_write_queue_mock &operator = (file_write_queue_mock const &) = delete;

   void expect_close()
   {
      expect_error(std::error_code{});
      ready_to_close();
   }

   template<typename error_code_matcher>
   void expect_error(error_code_matcher errorCodeMatcher)
   {
      executor().execute(
         [this, errorCodeMatcher = std::move(errorCodeMatcher)] ()
         {
            EXPECT_CALL(*this, io_closed(testing::_))
               .WillOnce(
                  [this, errorCodeMatcher = std::move(errorCodeMatcher)] (auto const errorCode)
                  {
                     super::io_closed(errorCode);
                     EXPECT_THAT(errorCode, errorCodeMatcher) << errorCode.value() << ": " << errorCode.message();
                     EXPECT_CALL(*this, io_closed(testing::_)).Times(0);
                     EXPECT_CALL(*this, io_ready_to_open()).Times(0);
                     assert(nullptr != m_internalState);
                     m_internalState->done.set_value();
                  }
               )
            ;
         }
      );
   }

   void expect_ready_to_open(file_writer_config testConfig)
   {
      m_internalState = std::make_unique<internal_state>();
      executor().execute(
         [this, testConfig = std::move(testConfig)] ()
         {
            EXPECT_CALL(*this, io_ready_to_open()).WillOnce(testing::Return(std::move(testConfig)));
         }
      );
      ready_to_open();
   }

   [[nodiscard]] auto wait_for(std::chrono::seconds const timeout) const
   {
      assert(nullptr != m_internalState);
      return m_internalState->doneFuture.wait_for(timeout);
   }

private:
   std::unique_ptr<internal_state> m_internalState{nullptr,};

   MOCK_METHOD(void, io_closed, (std::error_code const &), (override));
   MOCK_METHOD(file_writer_config, io_ready_to_open, (), (override));
};

using test_file_write_queue = testing::StrictMock<file_write_queue_mock>;

struct file_writer_test_data
{
   std::filesystem::path filePath;
   std::unique_ptr<test_file_write_queue> queue;
   std::deque<std::string> data;
};

using file_writer = testsuite;

}

TEST_F(file_writer, file_write_queue)
{
   auto const testDirectory = std::filesystem::temp_directory_path() / std::string{"io_thread_test_"}.append(random_string(10));
   std::filesystem::remove_all(testDirectory);
   std::filesystem::create_directories(testDirectory);
   {
      constexpr size_t testFileListCapacity{1000,};
      constexpr size_t testIoBufferSize{2 * 1024,}; ///< 2 KiB
      file_writer_thread const testThread{thread_config{}, testFileListCapacity, testIoBufferSize,};
      std::vector<file_writer_test_data> testFileWriters;
      testFileWriters.reserve(testFileListCapacity);
      constexpr size_t testMinStringLength = 1024; ///< 1 KiB
      constexpr size_t testMaxStringLength = 5 * 1024; ///< 5 KiB
      for (size_t testIndex = 0; testIndex < testFileListCapacity; ++testIndex)
      {
         auto testFilePath = testDirectory / random_string(10).append(".test");
         testFileWriters.push_back(
            file_writer_test_data
            {
               .filePath = testFilePath,
               .queue = std::make_unique<test_file_write_queue>(testThread),
               .data = std::deque<std::string>{},
            }
         );
         testFileWriters.back().queue->expect_ready_to_open(file_writer_config{testFilePath, file_writer_option::create_new});
         testFileWriters.back().data.push_back(random_string(testMinStringLength, testMaxStringLength));
         testFileWriters.back().queue->push(testFileWriters.back().data.back());
      }
      constexpr size_t testIterationsCount = testFileListCapacity * 10;
      for (size_t testIteration = 0; testIteration < testIterationsCount; ++testIteration)
      {
         auto &testData = testFileWriters[random_number<size_t>(0, testFileListCapacity - 1)];
         testData.data.push_back(random_string(testMinStringLength, testMaxStringLength));
         testData.queue->push(testData.data.back());
      }
      for (auto &testFileWriter : testFileWriters)
      {
         testFileWriter.queue->expect_close();
      }
      for (auto &testFileWriter : testFileWriters)
      {
         EXPECT_EQ(std::future_status::ready, testFileWriter.queue->wait_for(std::chrono::minutes{1}));
      }
      std::string testData;
      for (auto &testFileWriter : testFileWriters)
      {
         testFileWriter.queue.reset();
         std::ifstream testFile{testFileWriter.filePath, std::ios::binary | std::ios::in};
         for (auto const &expectedData : testFileWriter.data)
         {
            testData.resize(expectedData.size());
            EXPECT_TRUE(testFile.read(testData.data(), testData.size()));
            EXPECT_EQ(expectedData, testData);
         }
         testFile.close();
      }
      testFileWriters.clear();
   }
   std::filesystem::remove_all(testDirectory);
}

}
