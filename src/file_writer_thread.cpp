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

#include "io_threads/file_writer.hpp" ///< for io_threads::file_writer
#include "io_threads/file_writer_thread.hpp" ///< for io_threads::file_writer_thread
#if (defined(__linux__))
#  include "linux/file_writer_thread_worker.hpp" ///< for io_threads::file_writer::file_writer_thread_worker
#elif (defined(_WIN32) || defined(_WIN64))
#  include "windows/file_writer_thread_worker.hpp" ///< for io_threads::file_writer::file_writer_thread_worker
#endif

#include <cassert> ///< for assert
#include <cstddef> ///< for size_t
#include <cstdint> ///< for uint16_t
#include <functional> ///< for std::function
#include <future> ///< for std::future, std::promise
#include <memory> ///< for std::make_shared, std::shared_ptr
#include <thread> ///< for std::jthread
#include <utility> ///< for std::move

namespace io_threads
{

class file_writer_thread::file_writer_thread_impl final
{
public:
   file_writer_thread_impl() = delete;
   file_writer_thread_impl(file_writer_thread_impl &&) = delete;
   file_writer_thread_impl(file_writer_thread_impl const &) = delete;

   file_writer_thread_impl(uint16_t const coreCpuId, size_t const capacityOfFileDescriptorList)
   {
      assert(0 < capacityOfFileDescriptorList);
      std::promise<std::shared_ptr<file_writer::file_writer_thread_worker>> workerPromise{};
      auto workerFuture{workerPromise.get_future(),};
      m_thread = file_writer::file_writer_thread_worker::start(coreCpuId, capacityOfFileDescriptorList, workerPromise);
      m_worker = workerFuture.get();
   }

   ~file_writer_thread_impl()
   {
      assert(nullptr != m_worker);
      assert(false == m_thread.get_stop_token().stop_requested());
      m_thread.request_stop();
      m_worker->stop();
      m_worker.reset();
      m_thread.join();
   }

   file_writer_thread_impl &operator = (file_writer_thread_impl &&) = delete;
   file_writer_thread_impl &operator = (file_writer_thread_impl const &) = delete;

   void execute(std::function<void()> const &ioRoutine) const
   {
      assert(true == (bool{ioRoutine,}));
      assert(nullptr != m_worker);
      m_worker->execute(ioRoutine);
   }

   void ready_to_close(file_writer &writer) const
   {
      assert(nullptr != m_worker);
      m_worker->ready_to_close(writer);
   }

   void ready_to_open(file_writer &writer) const
   {
      assert(nullptr != m_worker);
      m_worker->ready_to_open(writer);
   }

   void ready_to_write(file_writer &writer) const
   {
      assert(nullptr != m_worker);
      m_worker->ready_to_write(writer);
   }

private:
   std::shared_ptr<file_writer::file_writer_thread_worker> m_worker{nullptr,};
   std::jthread m_thread{};
};

file_writer_thread::file_writer_thread(file_writer_thread &&rhs) noexcept :
   m_impl{std::move(rhs.m_impl),}
{
   assert(nullptr != m_impl);
}

file_writer_thread::file_writer_thread(file_writer_thread const &rhs) noexcept :
   m_impl{rhs.m_impl,}
{
   assert(nullptr != m_impl);
}

file_writer_thread::file_writer_thread(uint16_t const coreCpuId, size_t const capacityOfFileDescriptorList) :
   m_impl{std::make_shared<file_writer_thread_impl>(coreCpuId, capacityOfFileDescriptorList),}
{
   assert(nullptr != m_impl);
}

file_writer_thread::~file_writer_thread() = default;

file_writer_thread &file_writer_thread::operator = (file_writer_thread &&rhs) noexcept
{
   m_impl.swap(rhs.m_impl);
   assert(nullptr != m_impl);
   return *this;
}

file_writer_thread &file_writer_thread::operator = (file_writer_thread const &rhs)
{
   m_impl = rhs.m_impl;
   assert(nullptr != m_impl);
   return *this;
}

void file_writer_thread::execute(std::function<void()> const &ioRoutine) const
{
   assert(true == (bool{ioRoutine,}));
   assert(nullptr != m_impl);
   m_impl->execute(ioRoutine);
}

file_writer_thread::file_writer::file_writer(file_writer_thread const &fileWriterThread) noexcept :
   m_fileWriterThread{fileWriterThread.m_impl,}
{
   assert(nullptr != m_fileWriterThread);
}

file_writer_thread::file_writer::~file_writer()
{
   assert(nullptr != m_fileWriterThread);
}

void file_writer_thread::file_writer::ready_to_close()
{
   assert(nullptr != m_fileWriterThread);
   m_fileWriterThread->ready_to_close(*this);
}

void file_writer_thread::file_writer::ready_to_open()
{
   assert(nullptr != m_fileWriterThread);
   m_fileWriterThread->ready_to_open(*this);
}

void file_writer_thread::file_writer::ready_to_write()
{
   assert(nullptr != m_fileWriterThread);
   m_fileWriterThread->ready_to_write(*this);
}

}
