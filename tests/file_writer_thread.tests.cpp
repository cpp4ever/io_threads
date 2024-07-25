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

#include <io_threads/file_writer_thread.hpp>

#include <thread>

namespace io_threads::tests
{

namespace
{

file_writer_thread create_test_file_writer_thread()
{
   constexpr uint16_t testThreadCpuAffinity{0,};
   constexpr size_t testFileListCapacity{1,};
   constexpr size_t testIoBufferCapacity{1,};
   return file_writer_thread
   {
      file_writer_thread_config{testFileListCapacity, testIoBufferCapacity,}
         .with_poll_cpu_affinity(testThreadCpuAffinity)
         .with_io_cpu_affinity(testThreadCpuAffinity)
      ,
   };
}

using file_writer = testsuite;

}

TEST_F(file_writer, file_writer_thread)
{
   auto const testFileWriterThread1{create_test_file_writer_thread(),};
   std::thread::id testThread1Id{};
   {
      bool testOk{false,};
      testFileWriterThread1.execute([&testThread1Id, &testOk] () { testThread1Id = std::this_thread::get_id(); testOk = true; });
      ASSERT_TRUE(testOk);
   }
   auto testFileWriterThread2{create_test_file_writer_thread(),};
   std::thread::id testThread2Id{};
   {
      bool testOk{false,};
      testFileWriterThread2.execute([&testThread2Id, &testOk] () { testThread2Id = std::this_thread::get_id(); testOk = true; });
      ASSERT_TRUE(testOk);
   }
   file_writer_thread testFileWriterThread3{testFileWriterThread1,};
   {
      bool testOk{false,};
      testFileWriterThread3.execute([testThread1Id, &testOk] () { testOk = bool{testThread1Id == std::this_thread::get_id(),}; });
      EXPECT_TRUE(testOk);
   }
   testFileWriterThread3 = file_writer_thread{std::move(testFileWriterThread2),};
   {
      bool testOk{false,};
      testFileWriterThread3.execute([testThread2Id, &testOk] () { testOk = bool{testThread2Id == std::this_thread::get_id(),}; });
      EXPECT_TRUE(testOk);
   }
   testFileWriterThread3 = testFileWriterThread1;
   {
      bool testOk{false,};
      testFileWriterThread3.execute([testThread1Id, &testOk] () { testOk = bool{testThread1Id == std::this_thread::get_id(),}; });
      EXPECT_TRUE(testOk);
   }
}

}
