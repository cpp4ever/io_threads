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

#pragma once

#include "io_threads/data_chunk.hpp" ///< for io_threads::data_chunk
#include "io_threads/file_writer_config.hpp" ///< for io_threads::file_writer_config
#include "io_threads/file_writer_thread.hpp" ///< for io_threads::file_writer_thread

#include <memory> ///< for std::shared_ptr
#include <system_error> ///< for std::error_code

namespace io_threads
{

struct file_descriptor;

class file_writer_thread::file_writer
{
public:
   class file_writer_thread_worker;

   file_writer() = delete;
   file_writer(file_writer &&) = delete;
   file_writer(file_writer const &) = delete;
   [[nodiscard]] explicit file_writer(file_writer_thread const &fileWriterThread) noexcept;
   virtual ~file_writer();

   file_writer &operator = (file_writer &&) = delete;
   file_writer &operator = (file_writer const &) = delete;

protected:
   virtual void io_closed(std::error_code const &errorCode) = 0;
   virtual void io_opened() = 0;

   void ready_to_close();
   void ready_to_open();
   void ready_to_write();

private:
   file_descriptor *m_fileDescriptor{nullptr,};
   std::shared_ptr<file_writer_thread::file_writer_thread_impl> const m_fileWriterThread;

   [[nodiscard]] virtual file_writer_config io_ready_to_open() = 0;
   [[nodiscard]] virtual size_t io_ready_to_write(data_chunk const &dataChunk) = 0;
};

using file_writer [[maybe_unused]] = file_writer_thread::file_writer;

}
