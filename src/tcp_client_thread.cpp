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

#include "io_threads/tcp_client.hpp" ///< for io_threads::tcp_client
#include "io_threads/tcp_client_thread.hpp" ///< for io_threads::tcp_client_thread
#if (defined(__APPLE__))
#  include "macos/tcp_client_thread_impl.hpp" ///< for io_threads::tcp_client_thread::tcp_client_thread_impl
#elif (defined(__linux__))
#  include "linux/tcp_client_thread_impl.hpp" ///< for io_threads::tcp_client_thread::tcp_client_thread_impl
#elif (defined(_WIN32) || defined(_WIN64))
#  include "windows/tcp_client_thread_impl.hpp" ///< for io_threads::tcp_client_thread::tcp_client_thread_impl
#endif

#include <cassert> ///< for assert
#include <cstddef> ///< for size_t
#include <cstdint> ///< for uint16_t
#include <memory> ///< for std::make_shared
#include <utility> ///< for std::move

namespace io_threads
{

tcp_client_thread::tcp_client_thread(tcp_client_thread &&rhs) noexcept :
   m_impl(std::move(rhs.m_impl))
{
   assert(nullptr != m_impl);
}

tcp_client_thread::tcp_client_thread(tcp_client_thread const &rhs) noexcept :
   m_impl(rhs.m_impl)
{
   assert(nullptr != m_impl);
}

tcp_client_thread::tcp_client_thread(
   uint16_t const cpuId,
   size_t const initialCapacityOfSocketDescriptorList,
   size_t const recvBufferSize,
   size_t const sendBufferSize
) :
   m_impl(std::make_shared<tcp_client_thread_impl>(cpuId, initialCapacityOfSocketDescriptorList, recvBufferSize, sendBufferSize))
{
   assert(nullptr != m_impl);
}

tcp_client_thread::~tcp_client_thread() = default;

tcp_client_thread &tcp_client_thread::operator = (tcp_client_thread &&rhs) noexcept
{
   m_impl.swap(rhs.m_impl);
   assert(nullptr != m_impl);
   return *this;
}

tcp_client_thread &tcp_client_thread::operator = (tcp_client_thread const &rhs)
{
   m_impl = rhs.m_impl;
   assert(nullptr != m_impl);
   return *this;
}

tcp_client_thread::tcp_client::tcp_client(tcp_client_thread const &tcpClientThread) :
   m_thread(tcpClientThread.m_impl)
{
   assert(nullptr != m_thread);
   assert(nullptr == m_socketDescriptor);
}

tcp_client_thread::tcp_client::~tcp_client()
{
   assert(nullptr != m_thread);
   assert(nullptr == m_socketDescriptor);
}

void tcp_client_thread::tcp_client::ready_to_connect()
{
   assert(nullptr != m_thread);
   assert(nullptr == m_socketDescriptor);
   m_thread->ready_to_connect(*this);
}

void tcp_client_thread::tcp_client::ready_to_disconnect()
{
   assert(nullptr != m_thread);
   assert(nullptr != m_socketDescriptor);
   m_thread->ready_to_disconnect(*this);
}

void tcp_client_thread::tcp_client::ready_to_send()
{
   assert(nullptr != m_thread);
   assert(nullptr != m_socketDescriptor);
   m_thread->ready_to_send(*this);
}

}
