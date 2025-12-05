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

#pragma once

#include "io_threads/cpu_id.hpp" ///< for io_threads::cpu_id

#include <cstdint> ///< for uint32_t
#include <optional> ///< for std::nullopt, std::nullopt_t, std::optional
#if (defined(__linux__))
#  include <variant> ///< for std::variant
#endif

namespace io_threads
{

#if (defined(__linux__))
enum struct io_ring : int
{};

using io_affinity = std::variant<std::nullopt_t, cpu_id, io_ring>;
#endif

class thread_config
{
public:
   [[maybe_unused, nodiscard]] thread_config() noexcept = default;
   [[maybe_unused, nodiscard]] thread_config(thread_config &&rhs) noexcept = default;
   [[maybe_unused, nodiscard]] thread_config(thread_config const &rhs) noexcept = default;

   [[maybe_unused]] thread_config &operator = (thread_config &&rhs) noexcept = default;
   [[maybe_unused]] thread_config &operator = (thread_config const &rhs) noexcept = default;

   [[maybe_unused, nodiscard]] std::optional<cpu_id> worker_affinity() const noexcept
   {
      return m_workerAffinity;
   }

#if (defined(__linux__))
   [[maybe_unused, nodiscard]] io_affinity const &async_workers_affinity() const noexcept
   {
      return m_asyncWorkersAffinity;
   }

   [[maybe_unused, nodiscard]] io_affinity const &kernel_thread_affinity() const noexcept
   {
      return m_kernelThreadAffinity;
   }

   [[nodiscard]] thread_config with_io_threads_affinity(io_ring sharedIoThreads) const noexcept;
   [[nodiscard]] thread_config with_io_threads_affinity(cpu_id asyncWorkersAffinity, std::optional<cpu_id> kernelThreadAffinity) const noexcept;
   [[nodiscard]] thread_config with_io_threads_affinity(io_ring sharedAsyncWorkers, std::optional<cpu_id> kernelThreadAffinity) const noexcept;
#else
   [[nodiscard]] thread_config with_io_threads_affinity(std::nullopt_t const) const noexcept;
   [[nodiscard]] thread_config with_io_threads_affinity(std::optional<cpu_id> const, std::optional<cpu_id> const) const noexcept;
#endif
   [[nodiscard]] thread_config with_worker_affinity(cpu_id const value) const noexcept;

private:
   std::optional<cpu_id> m_workerAffinity{std::nullopt,};
#if (defined(__linux__))
   io_affinity m_asyncWorkersAffinity{std::nullopt,};
   io_affinity m_kernelThreadAffinity{std::nullopt,};
#endif
};

}
