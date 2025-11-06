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

/// for
///   io_threads::cpu_affinity_config,
///   io_threads::cpu_id,
///   io_threads::shared_cpu_affinity_config,
///   io_threads::thread_config
#include "io_threads/thread_config.hpp"

#include <cassert> ///< for assert
#include <cstddef> ///< for size_t

namespace io_threads
{

thread_config::thread_config(size_t const descriptorListCapacity, size_t const ioBufferCapacity) noexcept :
   m_descriptorListCapacity{descriptorListCapacity,},
   m_ioBufferCapacity{ioBufferCapacity,}
{
   assert(0 < m_descriptorListCapacity);
   assert(0 < m_ioBufferCapacity);
}

thread_config thread_config::with_io_threads_affinity([[maybe_unused]] cpu_affinity_config const cpuAffinity) const noexcept
{
   thread_config threadConfig{*this,};
#if (defined(__linux__))
   threadConfig.m_ioThreadsAffinity.emplace<cpu_affinity_config>(cpuAffinity);
#endif
   return threadConfig;
}

thread_config thread_config::with_io_threads_affinity([[maybe_unused]] shared_cpu_affinity_config const cpuAffinity) const noexcept
{
   thread_config threadConfig{*this,};
#if (defined(__linux__))
   threadConfig.m_ioThreadsAffinity.emplace<shared_cpu_affinity_config>(cpuAffinity);
#endif
   return threadConfig;
}

thread_config thread_config::with_worker_cpu_affinity(cpu_id const value) const noexcept
{
   thread_config threadConfig{*this,};
   threadConfig.m_workerCpuAffinity.emplace(value);
   return threadConfig;
}

}
