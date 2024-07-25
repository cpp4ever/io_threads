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

#include "testsuite.hpp" ///< for io_threads::tests::testsuite

#include "io_threads/file_writer_thread.hpp" ///< for io_threads::file_writer_thread

namespace io_threads::tests
{

static io_threads::file_writer_thread create_test_file_writer_thread()
{
   return io_threads::file_writer_thread{0, 0};
}

using file_writer_thread = testsuite;

TEST_F(file_writer_thread, file_writer_thread)
{
   auto const testFileWriterThread1 = create_test_file_writer_thread();
   auto testFileWriterThread2 = create_test_file_writer_thread();
   io_threads::file_writer_thread testFileWriterThread3 = testFileWriterThread1;
   testFileWriterThread3 = io_threads::file_writer_thread{std::move(testFileWriterThread2)};
   testFileWriterThread3 = io_threads::file_writer_thread{testFileWriterThread1};
}

}
