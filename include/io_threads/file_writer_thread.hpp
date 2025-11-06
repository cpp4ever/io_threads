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

#include "io_threads/thread_config.hpp" ///< for io_threads::shared_cpu_affinity_config, io_threads::thread_config

#include <functional> ///< for std::function
#include <memory> ///< for std::shared_ptr
#include <optional> ///< for std::nullopt

namespace io_threads
{

class file_writer_thread final
{
public:
   class file_writer;

   file_writer_thread() = delete;
   [[nodiscard]] file_writer_thread(file_writer_thread &&rhs) noexcept;
   [[nodiscard]] file_writer_thread(file_writer_thread const &rhs) noexcept;
   [[nodiscard]] explicit file_writer_thread(thread_config const &threadConfig);
   ~file_writer_thread();

   file_writer_thread &operator = (file_writer_thread &&) = delete;
   file_writer_thread &operator = (file_writer_thread const &) = delete;

   void execute(std::function<void()> const &ioRoutine) const;

#if (defined(__linux__))
   [[nodiscard]] shared_cpu_affinity_config share_io_threads() const noexcept;
#else
   [[maybe_unused, nodiscard]] constexpr shared_cpu_affinity_config share_io_threads() const noexcept
   {
      return std::nullopt;
   }
#endif

private:
   class file_writer_thread_impl;
   std::shared_ptr<file_writer_thread_impl> const m_impl;
};

}
