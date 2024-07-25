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
#include "io_threads/tcp_client_thread.hpp" ///< for io_threads::tcp_client_thread, io_threads::tcp_client_thread_config
#if (defined(__linux__))
#  include "linux/tcp_client_thread_worker.hpp" ///< for io_threads::tcp_client::tcp_client_thread_worker
#elif (defined(_WIN32) || defined(_WIN64))
#  include "windows/tcp_client_thread_worker.hpp" ///< for io_threads::tcp_client::tcp_client_thread_worker
#endif

#include <cassert> ///< for assert
#include <cstddef> ///< for size_t
#include <cstdint> ///< for uint16_t
#include <functional> ///< for std::function
#include <future> ///< for std::future, std::promise
#include <memory> ///< for std::addressof, std::make_shared
#include <thread> ///< for std::jthread
#include <utility> ///< for std::move

namespace io_threads
{

tcp_client_thread_config::tcp_client_thread_config(size_t const socketListCapacity, size_t const ioBufferCapacity) noexcept :
   m_socketListCapacity{socketListCapacity,},
   m_ioBufferCapacity{ioBufferCapacity,}
{
   assert(0 < m_socketListCapacity);
   assert(0 < m_ioBufferCapacity);
}

tcp_client_thread_config tcp_client_thread_config::with_io_cpu_affinity(uint16_t const value) const noexcept
{
   tcp_client_thread_config tcpClientThreadConfig{*this,};
   tcpClientThreadConfig.m_ioCpuAffinity.emplace(value);
   return tcpClientThreadConfig;
}

tcp_client_thread_config tcp_client_thread_config::with_poll_cpu_affinity(uint16_t const value) const noexcept
{
   tcp_client_thread_config tcpClientThreadConfig{*this,};
   tcpClientThreadConfig.m_pollCpuAffinity.emplace(value);
   if (false == tcpClientThreadConfig.m_ioCpuAffinity.has_value())
   {
      tcpClientThreadConfig.m_ioCpuAffinity.emplace(value);
   }
   return tcpClientThreadConfig;
}

class tcp_client_thread::tcp_client_thread_impl final
{
public:
   tcp_client_thread_impl() = delete;
   tcp_client_thread_impl(tcp_client_thread_impl &&) = delete;
   tcp_client_thread_impl(tcp_client_thread_impl const &) = delete;

   [[nodiscard]] explicit tcp_client_thread_impl(tcp_client_thread_config const &tcpClientThreadConfig)
   {
      std::promise<std::shared_ptr<tcp_client::tcp_client_thread_worker>> workerPromise{};
      auto workerFuture{workerPromise.get_future(),};
      m_thread = tcp_client::tcp_client_thread_worker::start(tcpClientThreadConfig, workerPromise);
      m_worker = workerFuture.get();
   }

   ~tcp_client_thread_impl()
   {
      m_thread.request_stop();
      m_worker->stop();
      m_worker.reset();
      m_thread.join();
   }

   tcp_client_thread_impl &operator = (tcp_client_thread_impl &&) = delete;
   tcp_client_thread_impl &operator = (tcp_client_thread_impl const &) = delete;

   void execute(std::function<void()> const &ioRoutine) const
   {
      m_worker->execute(ioRoutine);
   }

   void ready_to_connect(tcp_client &client) const
   {
      m_worker->ready_to_connect(client);
   }

   void ready_to_disconnect(tcp_client &client) const
   {
      m_worker->ready_to_disconnect(client);
   }

   void ready_to_send(tcp_client &client) const
   {
      m_worker->ready_to_send(client);
   }

private:
   std::shared_ptr<tcp_client::tcp_client_thread_worker> m_worker{nullptr,};
   std::jthread m_thread{};
};

tcp_client_thread::tcp_client_thread(tcp_client_thread &&rhs) noexcept = default;
tcp_client_thread::tcp_client_thread(tcp_client_thread const &rhs) noexcept = default;

tcp_client_thread::tcp_client_thread(tcp_client_thread_config const &tcpClientThreadConfig) :
   m_impl{std::make_shared<tcp_client_thread_impl>(tcpClientThreadConfig),}
{}

tcp_client_thread::~tcp_client_thread() = default;

tcp_client_thread &tcp_client_thread::operator = (tcp_client_thread &&rhs) noexcept = default;
tcp_client_thread &tcp_client_thread::operator = (tcp_client_thread const &rhs) = default;

void tcp_client_thread::execute(std::function<void()> const &ioRoutine) const
{
   assert(true == (bool{ioRoutine,}));
   m_impl->execute(ioRoutine);
}

tcp_client_thread::tcp_client::tcp_client(tcp_client_thread const &tcpClientThread) :
   m_tcpClientThread{tcpClientThread.m_impl,}
{}

tcp_client_thread::tcp_client::~tcp_client() = default;

void tcp_client_thread::tcp_client::ready_to_connect()
{
   m_tcpClientThread->ready_to_connect(*this);
}

void tcp_client_thread::tcp_client::ready_to_disconnect()
{
   m_tcpClientThread->ready_to_disconnect(*this);
}

void tcp_client_thread::tcp_client::ready_to_send()
{
   m_tcpClientThread->ready_to_send(*this);
}

}
