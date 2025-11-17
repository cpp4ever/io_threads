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

#include <io_threads/tcp_client_thread.hpp>

#include <thread>

namespace io_threads::tests
{

namespace
{

using tcp_client = testsuite;

}

TEST_F(tcp_client, tcp_client_thread)
{
   constexpr cpu_id testThreadCpuAffinity{0,};
   constexpr uint32_t testSocketListCapacity{1,};
   constexpr uint32_t testRecvBufferSize{1,};
   constexpr uint32_t testSendBufferSize{1,};
   tcp_client_thread const testTcpClientThread1
   {
      thread_config{}
         .with_worker_affinity(testThreadCpuAffinity)
         .with_io_threads_affinity(testThreadCpuAffinity, testThreadCpuAffinity)
      ,
      testSocketListCapacity,
      testRecvBufferSize,
      testSendBufferSize,
   };
   std::thread::id testThread1Id{};
   {
      bool testOk{false,};
      testTcpClientThread1.execute([&testThread1Id, &testOk] () { testThread1Id = std::this_thread::get_id(); testOk = true; });
      ASSERT_TRUE(testOk);
   }
   tcp_client_thread const testTcpClientThread2
   {
      thread_config{}
         .with_worker_affinity(testThreadCpuAffinity)
         .with_io_threads_affinity(testTcpClientThread1.share_io_threads())
      ,
      testSocketListCapacity,
      testRecvBufferSize,
      testSendBufferSize,
   };
   {
      bool testOk{false,};
      testTcpClientThread2.execute([testThread1Id, &testOk] () { testOk = bool{testThread1Id != std::this_thread::get_id(),}; });
      ASSERT_TRUE(testOk);
   }
   tcp_client_thread testTcpClientThread3{testTcpClientThread1,};
   {
      bool testOk{false,};
      testTcpClientThread3.execute([testThread1Id, &testOk] () { testOk = bool{testThread1Id == std::this_thread::get_id(),}; });
      EXPECT_TRUE(testOk);
   }
}

}
