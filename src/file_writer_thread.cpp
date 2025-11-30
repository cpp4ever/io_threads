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

#include "io_threads/file_writer.hpp" ///< for io_threads::file_writer
#include "io_threads/file_writer_thread.hpp" ///< for io_threads::file_writer_thread
#include "io_threads/thread_config.hpp" ///< for io_threads::io_ring, io_threads::thread_config
#if (defined(__linux__))
#  include "linux/file_writer_thread_worker.hpp" ///< for io_threads::file_writer::file_writer_thread_worker
#elif (defined(_WIN32) || defined(_WIN64))
#  include "windows/file_writer_thread_worker.hpp" ///< for io_threads::file_writer::file_writer_thread_worker
#endif

#include <cassert> ///< for assert
#include <cstdint> ///< for uint32_t
#include <functional> ///< for std::function
#include <future> ///< for std::future, std::promise
#include <memory> ///< for std::make_shared, std::shared_ptr
#include <thread> ///< for std::thread
#include <utility> ///< for std::move

namespace io_threads
{

class file_writer_thread::file_writer_thread_impl final
{
public:
   file_writer_thread_impl() = delete;
   file_writer_thread_impl(file_writer_thread_impl &&) = delete;
   file_writer_thread_impl(file_writer_thread_impl const &) = delete;

   [[nodiscard]] file_writer_thread_impl(thread_config const &threadConfig, uint32_t const fileListCapacity, uint32_t const ioBufferSize)
   {
      assert(0 < fileListCapacity);
      assert(0 < ioBufferSize);
      std::promise<std::shared_ptr<file_writer::file_writer_thread_worker>> workerPromise{};
      auto workerFuture{workerPromise.get_future(),};
      m_thread = file_writer::file_writer_thread_worker::start(threadConfig, fileListCapacity, ioBufferSize, workerPromise);
      m_worker = workerFuture.get();
   }

   ~file_writer_thread_impl()
   {
      m_worker->stop();
      m_worker.reset();
      m_thread.join();
   }

   file_writer_thread_impl &operator = (file_writer_thread_impl &&) = delete;
   file_writer_thread_impl &operator = (file_writer_thread_impl const &) = delete;

   void execute(std::function<void()> const &ioRoutine) const
   {
      m_worker->execute(ioRoutine);
   }

   void ready_to_close(file_writer &writer) const
   {
      m_worker->ready_to_close(writer);
   }

   void ready_to_open(file_writer &writer) const
   {
      m_worker->ready_to_open(writer);
   }

   void ready_to_write(file_writer &writer) const
   {
      m_worker->ready_to_write(writer);
   }

#if (defined(__linux__))
   [[nodiscard]] io_ring share_io_threads() const noexcept
   {
      return m_worker->share_io_threads();
   }
#endif

private:
   std::shared_ptr<file_writer::file_writer_thread_worker> m_worker{nullptr,};
   std::thread m_thread{};
};

file_writer_thread::file_writer_thread(file_writer_thread &&rhs) noexcept = default;
file_writer_thread::file_writer_thread(file_writer_thread const &rhs) noexcept = default;

file_writer_thread::file_writer_thread(thread_config const &threadConfig, uint32_t const fileListCapacity, uint32_t const ioBufferSize) :
   m_impl{std::make_shared<file_writer_thread_impl>(threadConfig, fileListCapacity, ioBufferSize),}
{}

file_writer_thread::~file_writer_thread() = default;

void file_writer_thread::execute(std::function<void()> const &ioRoutine) const
{
   assert(true == (bool{ioRoutine,}));
   m_impl->execute(ioRoutine);
}

#if (defined(__linux__))
io_ring file_writer_thread::share_io_threads() const noexcept
{
   return m_impl->share_io_threads();
}
#endif

file_writer_thread::file_writer::file_writer(file_writer_thread fileWriterThread) noexcept :
   m_fileWriterThread{std::move(fileWriterThread),}
{}

file_writer_thread::file_writer::~file_writer() = default;

void file_writer_thread::file_writer::ready_to_close()
{
   m_fileWriterThread.m_impl->ready_to_close(*this);
}

void file_writer_thread::file_writer::ready_to_open()
{
   m_fileWriterThread.m_impl->ready_to_open(*this);
}

void file_writer_thread::file_writer::ready_to_write()
{
   m_fileWriterThread.m_impl->ready_to_write(*this);
}

}
