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

#include <io_threads/tls_client_context.hpp>

#include <thread>

namespace io_threads::tests
{

namespace
{

tls_client_context create_test_tls_client_context(std::string_view const domainName)
{
   constexpr size_t testSocketListCapacity{1,};
   constexpr size_t testIoBufferCapacity{1,};
   tcp_client_thread const testThread{thread_config{testSocketListCapacity, testIoBufferCapacity,},};
   x509_store const x509Store{x509_store_config{},};
   constexpr size_t testTlsSessionListCapacity{1,};
   return tls_client_context{testThread, x509Store, domainName, testTlsSessionListCapacity,};
}

using tls_client = testsuite;

}

TEST_F(tls_client, tls_client_context)
{
   auto const testTlsClientContext1{create_test_tls_client_context("example.com"),};
   std::thread::id testThread1Id{};
   {
      bool testOk{false,};
      testTlsClientContext1.executor().execute([&testThread1Id, &testOk] () { testThread1Id = std::this_thread::get_id(); testOk = true; });
      ASSERT_TRUE(testOk);
   }
   auto testTlsClientContext2{create_test_tls_client_context("github.com"),};
   std::thread::id testThread2Id{};
   {
      bool testOk{false,};
      testTlsClientContext2.executor().execute([&testThread2Id, &testOk] () { testThread2Id = std::this_thread::get_id(); testOk = true; });
      ASSERT_TRUE(testOk);
   }
   tls_client_context testTlsClientContext3{testTlsClientContext1,};
   {
      bool testOk{false,};
      testTlsClientContext3.executor().execute([testThread1Id, &testOk] () { testOk = bool{testThread1Id == std::this_thread::get_id(),}; });
      EXPECT_TRUE(testOk);
   }
}

}
