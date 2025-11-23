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

#include "io_threads/thread_config.hpp" ///< for io_threads::cpu_id, io_threads::io_ring, io_threads::thread_config

#include <optional> ///< for std::nullopt, std::nullopt_t, std::optional

namespace io_threads
{

#if (defined(__linux__))
thread_config thread_config::with_io_threads_affinity(io_ring const sharedIoThreads) const noexcept
{
   thread_config threadConfig{*this,};
   threadConfig.m_asyncWorkersAffinity.emplace<io_ring>(sharedIoThreads);
   threadConfig.m_kernelThreadAffinity.emplace<io_ring>(sharedIoThreads);
   return threadConfig;
}

thread_config thread_config::with_io_threads_affinity(cpu_id asyncWorkersAffinity, std::optional<cpu_id> kernelThreadAffinity) const noexcept
{
   thread_config threadConfig{*this,};
   threadConfig.m_asyncWorkersAffinity.emplace<cpu_id>(asyncWorkersAffinity);
   if (true == kernelThreadAffinity.has_value())
   {
      threadConfig.m_kernelThreadAffinity.emplace<cpu_id>(kernelThreadAffinity.value());
   }
   else
   {
      threadConfig.m_kernelThreadAffinity.emplace<std::nullopt_t>(std::nullopt);
   }
   return threadConfig;
}

thread_config thread_config::with_io_threads_affinity(io_ring sharedAsyncWorkers, std::optional<cpu_id> kernelThreadAffinity) const noexcept
{
   thread_config threadConfig{*this,};
   threadConfig.m_asyncWorkersAffinity.emplace<io_ring>(sharedAsyncWorkers);
   if (true == kernelThreadAffinity.has_value())
   {
      threadConfig.m_kernelThreadAffinity.emplace<cpu_id>(kernelThreadAffinity.value());
   }
   else
   {
      threadConfig.m_kernelThreadAffinity.emplace<std::nullopt_t>(std::nullopt);
   }
   return threadConfig;
}
#else
thread_config thread_config::with_io_threads_affinity(std::nullopt_t const) const noexcept
{
   return *this;
}

thread_config thread_config::with_io_threads_affinity(std::optional<cpu_id> const, std::optional<cpu_id> const) const noexcept
{
   return *this;
}
#endif

thread_config thread_config::with_worker_affinity(cpu_id const value) const noexcept
{
   thread_config threadConfig{*this,};
   threadConfig.m_workerAffinity.emplace(value);
   return threadConfig;
}

}
