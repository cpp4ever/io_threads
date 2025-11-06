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

#include "common/logger.hpp" ///< for io_threads::log_error
#include "common/tcp_client_command.hpp" ///< for io_threads::tcp_client_command
#include "common/tcp_deferred_task.hpp" ///< for io_threads::tcp_client::tcp_deferred_task
#include "common/utility.hpp" ///< for io_threads::unreachable
#include "io_threads/tcp_client.hpp" ///< for io_threads::tcp_client
#include "io_threads/tcp_client_thread.hpp" ///< for io_threads::tcp_client_thread
#include "io_threads/thread_config.hpp" ///< for io_threads::shared_cpu_affinity_config, io_threads::thread_config
#include "io_threads/time.hpp" ///< for io_threads::system_clock, io_threads::system_time
#if (defined(__linux__))
#  include "linux/tcp_client_thread_worker.hpp" ///< for io_threads::tcp_client::tcp_client_thread_worker
#elif (defined(_WIN32) || defined(_WIN64))
#  include "windows/tcp_client_thread_worker.hpp" ///< for io_threads::tcp_client::tcp_client_thread_worker
#endif

#include <cassert> ///< for assert
#include <functional> ///< for std::function
#include <future> ///< for std::future, std::promise
#include <memory> ///< for std::addressof, std::make_shared
#include <source_location> ///< for std::source_location
#include <thread> ///< for std::jthread
#include <utility> ///< for std::move

namespace io_threads
{

class tcp_client_thread::tcp_client_thread_impl final
{
public:
   tcp_client_thread_impl() = delete;
   tcp_client_thread_impl(tcp_client_thread_impl &&) = delete;
   tcp_client_thread_impl(tcp_client_thread_impl const &) = delete;

   [[nodiscard]] explicit tcp_client_thread_impl(thread_config const &threadConfig)
   {
      std::promise<std::shared_ptr<tcp_client::tcp_client_thread_worker>> workerPromise{};
      auto workerFuture{workerPromise.get_future(),};
      m_thread = tcp_client::tcp_client_thread_worker::start(threadConfig, workerPromise);
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

   void ready_to_connect_deferred(tcp_client &client, system_time const notBeforeTime) const
   {
      m_worker->ready_to_connect_deferred(client, notBeforeTime);
   }

   void ready_to_disconnect(tcp_client &client) const
   {
      m_worker->ready_to_disconnect(client);
   }

   void ready_to_send(tcp_client &client) const
   {
      m_worker->ready_to_send(client);
   }

   void ready_to_send_deferred(tcp_client &client, system_time const notBeforeTime) const
   {
      m_worker->ready_to_send_deferred(client, notBeforeTime);
   }

#if (defined(__linux__))
   [[nodiscard]] shared_cpu_affinity_config share_io_threads() const noexcept
   {
      return m_worker->share_io_threads();
   }
#endif

private:
   std::shared_ptr<tcp_client::tcp_client_thread_worker> m_worker{nullptr,};
   std::jthread m_thread{};
};

tcp_client_thread::tcp_client_thread(tcp_client_thread &&rhs) noexcept = default;
tcp_client_thread::tcp_client_thread(tcp_client_thread const &rhs) noexcept = default;

tcp_client_thread::tcp_client_thread(thread_config const &threadConfig) :
   m_impl{std::make_shared<tcp_client_thread_impl>(threadConfig),}
{}

tcp_client_thread::~tcp_client_thread() = default;

void tcp_client_thread::execute(std::function<void()> const &ioRoutine) const
{
   assert(true == (bool{ioRoutine,}));
   m_impl->execute(ioRoutine);
}

#if (defined(__linux__))
shared_cpu_affinity_config tcp_client_thread::share_io_threads() const noexcept
{
   return m_impl->share_io_threads();
}
#endif

tcp_client_thread::tcp_client::tcp_client(tcp_client_thread tcpClientThread) noexcept :
   m_tcpClientThread{std::move(tcpClientThread),}
{}

tcp_client_thread::tcp_client::~tcp_client() = default;

void tcp_client_thread::tcp_client::ready_to_connect()
{
   m_tcpClientThread.m_impl->ready_to_connect(*this);
}

void tcp_client_thread::tcp_client::ready_to_connect_deferred(system_time const notBeforeTime)
{
   m_tcpClientThread.m_impl->ready_to_connect_deferred(*this, notBeforeTime);
}

void tcp_client_thread::tcp_client::ready_to_disconnect()
{
   m_tcpClientThread.m_impl->ready_to_disconnect(*this);
}

void tcp_client_thread::tcp_client::ready_to_send()
{
   m_tcpClientThread.m_impl->ready_to_send(*this);
}

void tcp_client_thread::tcp_client::ready_to_send_deferred(system_time const notBeforeTime)
{
   m_tcpClientThread.m_impl->ready_to_send_deferred(*this, notBeforeTime);
}

void tcp_client_thread::tcp_client::tcp_client_thread_worker::cancel_deferred_task(tcp_client &tcpClient)
{
   if (nullptr == tcpClient.m_deferredTask)
   {
      return;
   }
   auto &deferredTask{*tcpClient.m_deferredTask,};
   assert(std::addressof(tcpClient) == std::addressof(deferredTask.client));
   deferredTask.client.m_deferredTask = nullptr;
   if (auto *prevDeferredTask{deferredTask.prev,}; nullptr != prevDeferredTask)
   {
      assert(std::addressof(deferredTask) != m_deferredTaskHead);
      assert(std::addressof(deferredTask) == prevDeferredTask->next);
      deferredTask.prev = nullptr;
      if (auto *nextDeferredTask{deferredTask.next,}; nullptr != nextDeferredTask)
      {
         assert(std::addressof(deferredTask) == nextDeferredTask->prev);
         prevDeferredTask->next = nextDeferredTask;
         deferredTask.next = nullptr;
         nextDeferredTask->prev = prevDeferredTask;
      }
      else
      {
         assert(std::addressof(deferredTask) == m_deferredTaskTail);
         prevDeferredTask->next = nullptr;
         m_deferredTaskTail = prevDeferredTask;
      }
   }
   else if (auto *nextDeferredTask{deferredTask.next,}; nullptr != nextDeferredTask)
   {
      assert(std::addressof(deferredTask) == m_deferredTaskHead);
      assert(std::addressof(deferredTask) != m_deferredTaskTail);
      assert(std::addressof(deferredTask) == nextDeferredTask->prev);
      deferredTask.next = nullptr;
      m_deferredTaskHead = nextDeferredTask;
      nextDeferredTask->prev = nullptr;
   }
   else
   {
      assert(std::addressof(deferredTask) == m_deferredTaskHead);
      assert(std::addressof(deferredTask) == m_deferredTaskTail);
      m_deferredTaskHead = nullptr;
      m_deferredTaskTail = nullptr;
   }
   m_deferredTaskMemory->push(deferredTask);
}

void tcp_client_thread::tcp_client::tcp_client_thread_worker::enqueue_deferred_task(tcp_deferred_task &deferredTask)
{
   assert(nullptr == deferredTask.prev);
   assert(nullptr == deferredTask.next);
   assert(nullptr == deferredTask.client.m_deferredTask);
   assert((tcp_client_command::ready_to_connect == deferredTask.command) || (tcp_client_command::ready_to_send == deferredTask.command));
   if (nullptr == m_deferredTaskHead)
   {
      assert(nullptr == m_deferredTaskTail);
      m_deferredTaskHead = m_deferredTaskTail = std::addressof(deferredTask);
   }
   else if (deferredTask.notBeforeTime >= m_deferredTaskTail->notBeforeTime)
   {
      deferredTask.prev = m_deferredTaskTail;
      m_deferredTaskTail->next = std::addressof(deferredTask);
      m_deferredTaskTail = std::addressof(deferredTask);
   }
   else if (m_deferredTaskHead->notBeforeTime > deferredTask.notBeforeTime)
   {
      assert(nullptr != m_deferredTaskTail);
      deferredTask.next = m_deferredTaskHead;
      m_deferredTaskHead->prev = std::addressof(deferredTask);
      m_deferredTaskHead = std::addressof(deferredTask);
   }
   else
   {
      assert(nullptr != m_deferredTaskTail);
      for (
         auto *currDeferredTask{m_deferredTaskHead->next,};
         ;
         currDeferredTask = currDeferredTask->next
      )
      {
         if (currDeferredTask->notBeforeTime > deferredTask.notBeforeTime)
         {
            deferredTask.prev = currDeferredTask->prev;
            deferredTask.prev->next = std::addressof(deferredTask);
            deferredTask.next = currDeferredTask;
            currDeferredTask->prev = std::addressof(deferredTask);
            break;
         }
      }
   }
   deferredTask.client.m_deferredTask = std::addressof(deferredTask);
}

void tcp_client_thread::tcp_client::tcp_client_thread_worker::handle_deferred_task(tcp_deferred_task &deferredTask)
{
   assert(nullptr == deferredTask.prev);
   assert(nullptr == deferredTask.next);
   auto &client{deferredTask.client,};
   assert(nullptr == client.m_deferredTask);
   assert((tcp_client_command::ready_to_connect == deferredTask.command) || (tcp_client_command::ready_to_send == deferredTask.command));
   auto const command{deferredTask.command,};
   m_deferredTaskMemory->push(deferredTask);
   switch (command)
   {

   case tcp_client_command::ready_to_connect:
   {
      handle_ready_to_connect(client);
   }
   break;

   case tcp_client_command::ready_to_send:
   {
      handle_ready_to_send(client);
   }
   break;

   [[unlikely]] default:
   {
      log_error(std::source_location::current(), "[tcp_client] unexpected deferred command: it must be a bug");
      unreachable();
   }
   break;

   }
}

void tcp_client_thread::tcp_client::tcp_client_thread_worker::process_deferred_tasks()
{
   auto *deferredTask{m_deferredTaskHead,};
   while ((nullptr != deferredTask) && (system_clock::now() >= deferredTask->notBeforeTime))
   {
      assert(nullptr == deferredTask->prev);
      if (auto *nextDeferredTask{deferredTask->next,}; nullptr != nextDeferredTask)
      {
         assert(deferredTask == nextDeferredTask->prev);
         deferredTask->next = nullptr;
         m_deferredTaskHead = nextDeferredTask;
         nextDeferredTask->prev = nullptr;
      }
      else
      {
         assert(deferredTask == m_deferredTaskTail);
         m_deferredTaskHead = m_deferredTaskTail = nullptr;
      }
      deferredTask->client.m_deferredTask = nullptr;
      handle_deferred_task(*deferredTask);
      deferredTask = m_deferredTaskHead;
   }
}

}
