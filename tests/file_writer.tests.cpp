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

#include "testsuite.hpp"

#include "io_threads/file_writer.hpp"
#include "io_threads/file_writer_thread.hpp"
#include "io_threads/spin_lock.hpp"

#include <gmock/gmock.h> ///< for MOCK_METHOD
#include <gtest/gtest.h> ///< for TEST
#if (defined(_WIN32) || defined(_WIN64))
#  include <Windows.h>
#endif

#include <deque>
#include <fstream>
#include <functional>
#include <future>

namespace io_threads::tests
{

namespace
{

class file_writer_mock : public io_threads::file_writer
{
private:
   using super = io_threads::file_writer;

public:
   file_writer_mock() = delete;
   file_writer_mock(file_writer_mock &&) = delete;
   file_writer_mock(file_writer_mock const &) = delete;

   file_writer_mock(io_threads::file_writer_thread const &fileWriterThread, std::filesystem::path const &filePath) :
      super(fileWriterThread),
      m_filePath(filePath)
   {
      expect_open();
      ready_to_open();
   }

   file_writer_mock(
      io_threads::file_writer_thread const &fileWriterThread,
      std::filesystem::path const &filePath,
      std::function<void (std::error_code)> errorHandler
   ) :
      super(fileWriterThread),
      m_filePath(filePath)
   {
      expect_error(errorHandler);
      ready_to_open();
   }

   file_writer_mock &operator = (file_writer_mock &&) = delete;
   file_writer_mock &operator = (file_writer_mock const &) = delete;

   std::future<void> close()
   {
      auto future = m_done.get_future();
      [[maybe_unused]] std::scoped_lock const dataGuard(m_dataLock);
      if (true == m_asleep)
      {
         m_asleep = false;
         expect_close();
         ready_to_close();
      }
      assert(false == m_teardown);
      m_teardown = true;
      return future;
   }

   void push(std::string_view const data)
   {
      [[maybe_unused]] std::scoped_lock const dataGuard(m_dataLock);
      m_data.push_back(data);
      if (true == m_asleep)
      {
         m_asleep = false;
         ready_to_write();
      }
   }

   void reopen()
   {
      expect_open();
      ready_to_open();
   }

private:
   spin_lock m_dataLock;
   std::deque<std::string_view> m_data = {};
   bool m_asleep = false;
   bool m_teardown = false;
   std::promise<void> m_done = {};
   std::filesystem::path const m_filePath;

   void expect_close()
   {
      EXPECT_CALL(*this, io_closed(testing::_))
         .WillOnce(
            [this] (auto const errorCode)
            {
               EXPECT_FALSE(errorCode) << errorCode.value() << ":" << errorCode.message();
               m_done.set_value();
            }
         )
      ;
   }

   void expect_error(std::function<void (std::error_code)> handler)
   {
      assert(handler);
      EXPECT_CALL(*this, io_ready_to_open())
         .WillOnce(
            [this, handler] ()
            {
               EXPECT_CALL(*this, io_closed(testing::_))
                  .WillOnce(
                     [handler] (auto const errorCode)
                     {
                        handler(errorCode);
                     }
                  )
               ;
               return file_writer_config{m_filePath, file_writer_option::create_new};
            }
         )
      ;
   }

   void expect_open()
   {
      EXPECT_CALL(*this, io_ready_to_open())
         .WillOnce(
            [this] ()
            {
               EXPECT_CALL(*this, io_ready_to_write())
                  .WillRepeatedly(
                     [this] ()
                     {
                        [[maybe_unused]] std::scoped_lock const dataGuard(m_dataLock);
                        if (true == m_data.empty())
                        {
                           m_asleep = true;
                           if (true == m_teardown)
                           {
                              expect_close();
                              ready_to_close();
                           }
                           return data_chunk{};
                        }
                        auto const dataChunk = data_chunk
                        {
                           .bytes = std::bit_cast<std::byte *>(m_data.front().data()),
                           .bytesLength = m_data.front().size(),
                        };
                        m_data.pop_front();
                        return dataChunk;
                     }
                  )
               ;
               return file_writer_config{m_filePath, file_writer_option::create_or_open_and_truncate};
            }
         )
      ;
   }

   MOCK_METHOD(void, io_closed, (std::error_code testErrorCode), (override));
   MOCK_METHOD(file_writer_config, io_ready_to_open, (), (override));
   MOCK_METHOD(data_chunk, io_ready_to_write, (), (override));
};

using test_file_writer = testing::StrictMock<file_writer_mock>;

struct file_writer_test_data
{
   std::filesystem::path filePath;
   std::unique_ptr<test_file_writer> writer;
   std::deque<std::string> data;
};

using file_writer = testsuite;

}

TEST_F(file_writer, not_found)
{
   auto const testDirectory = std::filesystem::temp_directory_path() / std::string{"io_thread_test_"}.append(random_string(10));
   std::filesystem::remove_all(testDirectory);
   constexpr uint16_t testCpuId = 0;
   constexpr size_t testFileWritersCount = 0;
   auto const testFileWriterThread = io_threads::file_writer_thread{testCpuId, testFileWritersCount};
   auto testErrorPromise = std::promise<void>{};
   auto const testErrorFuture = testErrorPromise.get_future();
   test_file_writer testFileWriter
   {
      testFileWriterThread,
      testDirectory / random_string(10).append(".test"),
      [&testErrorPromise] (auto const errorCode)
      {
         EXPECT_TRUE(errorCode);
         testErrorPromise.set_value();
      }
   };
   EXPECT_EQ(std::future_status::ready, testErrorFuture.wait_for(std::chrono::seconds{1}));
   std::filesystem::create_directories(testDirectory);
   testFileWriter.reopen();
   auto const testCloseFuture = testFileWriter.close();
   if (true == testCloseFuture.valid())
   {
      EXPECT_EQ(std::future_status::ready, testCloseFuture.wait_for(std::chrono::seconds{1}));
   }
   std::filesystem::remove_all(testDirectory);
}

TEST_F(file_writer, mass_write)
{
   auto const testDirectory = std::filesystem::temp_directory_path() / std::string{"io_thread_test_"}.append(random_string(10));
   std::filesystem::remove_all(testDirectory);
   std::filesystem::create_directories(testDirectory);
   constexpr uint16_t testCpuId = 0;
   constexpr size_t testFileWritersCount = 1000;
   auto const testFileWriterThread = io_threads::file_writer_thread{testCpuId, testFileWritersCount};
   std::vector<file_writer_test_data> testFileWriters;
   testFileWriters.reserve(testFileWritersCount);
   for (size_t testIndex = 0; testIndex < testFileWritersCount; ++testIndex)
   {
      auto testFilePath = testDirectory / random_string(10).append(".test");
      testFileWriters.push_back(
         file_writer_test_data
         {
            .filePath = testFilePath,
            .writer = std::make_unique<test_file_writer>(testFileWriterThread, std::move(testFilePath)),
            .data = {},
         }
      );
      testFileWriters.back().data.push_back(random_string(1024));
      testFileWriters.back().writer->push(testFileWriters.back().data.back());
   }
   for (size_t testIteration = 0; testIteration < (testFileWritersCount * 10); ++testIteration)
   {
      auto &testData = testFileWriters[random_number<size_t>(0, testFileWritersCount - 1)];
      testData.data.push_back(random_string(1024));
      testData.writer->push(testData.data.back());
   }
   {
      std::vector<std::future<void>> testCloseFutures;
      testCloseFutures.reserve(testFileWritersCount);
      for (auto &testFileWriter : testFileWriters)
      {
         testCloseFutures.push_back(testFileWriter.writer->close());
         if (false == testCloseFutures.back().valid())
         {
            testCloseFutures.pop_back();
         }
      }
      for (auto &testCloseFuture : testCloseFutures)
      {
         EXPECT_EQ(std::future_status::ready, testCloseFuture.wait_for(std::chrono::minutes{1}));
      }
   }
   std::string testData;
   for (auto &testFileWriter : testFileWriters)
   {
      testFileWriter.writer.reset();
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
   std::error_code errorCode;
   std::filesystem::remove_all(testDirectory, errorCode);
#if (defined(_WIN32) || defined(_WIN64))
   if (errorCode)
   {
      EXPECT_NE(FALSE, CancelSynchronousIo(GetCurrentThread())) << GetLastError();
      errorCode = {};
      std::filesystem::remove_all(testDirectory, errorCode);
   }
#endif
   EXPECT_FALSE(errorCode) << errorCode.message();
}

}
