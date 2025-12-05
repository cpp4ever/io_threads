/*
   Part of the io_threads project (https://github.com/cpp4ever/io_threads), under the MIT License
   SPDX-License-Identifier: MIT

   Copyright (c) 2024-2025 Mikhail Smirnov

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

#include <gmock/gmock.h>
#include <io_threads/file_writer.hpp>
#include <io_threads/file_writer_thread.hpp>
#if (defined(_WIN32) || defined(_WIN64))
#  include <winerror.h>
#endif

#include <future>

namespace io_threads::tests
{

namespace
{

class file_writer_mock : public io_threads::file_writer
{
private:
   using super = io_threads::file_writer;

   struct internal_state final
   {
      std::promise<void> done{};
      std::future<void> doneFuture{done.get_future(),};
   };

public:
   using super::super;

   file_writer_mock &operator = (file_writer_mock &&) = delete;
   file_writer_mock &operator = (file_writer_mock const &) = delete;

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

   void io_opened() override
   {
      EXPECT_CALL(*this, io_ready_to_write(testing::_)).WillOnce(testing::Return(0));
   }

   MOCK_METHOD(file_writer_config, io_ready_to_open, (), (override));
   MOCK_METHOD(size_t, io_ready_to_write, (data_chunk const &), (override));
};

using test_file_writer = testing::StrictMock<file_writer_mock>;

using file_writer = testsuite;

}

TEST_F(file_writer, not_found)
{
#if (defined(__linux__))
   auto const testNotFoundErrorCode = std::make_error_code(std::errc::no_such_file_or_directory);
#elif (defined(_WIN32) || defined(_WIN64))
   std::error_code const testNotFoundErrorCode{ERROR_PATH_NOT_FOUND, std::system_category(),};
#endif
   auto const testDirectory{std::filesystem::temp_directory_path() / std::string{"io_thread_test_"}.append(random_string(10)),};
   std::filesystem::remove_all(testDirectory);
   {
      constexpr size_t testFileListCapacity{1,};
      constexpr size_t testIoBufferSize{1,};
      file_writer_thread const testThread{thread_config{}.with_worker_affinity(first_cpu()), testFileListCapacity, testIoBufferSize,};
      test_file_writer testFileWriter{testThread,};
      testFileWriter.expect_error(testNotFoundErrorCode);
      auto const testFilePath{testDirectory / random_string(10).append(".test"),};
      testFileWriter.expect_ready_to_open(file_writer_config{testFilePath, file_writer_option::create_new,});
      EXPECT_EQ(std::future_status::ready, testFileWriter.wait_for(std::chrono::seconds{1,}));
      std::filesystem::create_directories(testDirectory);
      testFileWriter.expect_ready_to_open(file_writer_config{testFilePath, file_writer_option::create_new,});
      testFileWriter.expect_close();
      EXPECT_EQ(std::future_status::ready, testFileWriter.wait_for(std::chrono::seconds{1,}));
   }
   std::filesystem::remove_all(testDirectory);
}

}
