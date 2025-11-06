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

#include <cstddef> ///< for size_t
#include <cstdint> ///< for uint32_t
#include <optional> ///< for std::nullopt, std::nullopt_t, std::optional
#if (defined(__linux__))
#  include <variant> ///< for std::variant
#endif

namespace io_threads
{

enum struct cpu_id : uint32_t
{};

class cpu_affinity_config final
{
public:
   cpu_affinity_config() = delete;
   [[maybe_unused, nodiscard]] cpu_affinity_config(cpu_affinity_config &&rhs) noexcept = default;
   [[maybe_unused, nodiscard]] cpu_affinity_config(cpu_affinity_config const &rhs) noexcept = default;

#if (defined(__linux__))
   [[maybe_unused, nodiscard]] cpu_affinity_config(cpu_id const asyncWorkersCpuId, cpu_id const kernelThreadCpuId) noexcept :
      m_asyncWorkersCpuId{asyncWorkersCpuId,},
      m_kernelThreadCpuId{kernelThreadCpuId,}
   {}
#else
   [[maybe_unused, nodiscard]] cpu_affinity_config(cpu_id const, cpu_id const) noexcept
   {}
#endif

   [[maybe_unused]] cpu_affinity_config &operator = (cpu_affinity_config &&rhs) noexcept = default;
   [[maybe_unused]] cpu_affinity_config &operator = (cpu_affinity_config const &rhs) noexcept = default;

#if (defined(__linux__))
   [[maybe_unused, nodiscard]] cpu_id async_workers_cpu_id() const noexcept
   {
      return m_asyncWorkersCpuId;
   }

   [[maybe_unused, nodiscard]] cpu_id kernel_thread_cpu_id() const noexcept
   {
      return m_kernelThreadCpuId;
   }

private:
   cpu_id m_asyncWorkersCpuId;
   cpu_id m_kernelThreadCpuId;
#endif
};

#if (defined(__linux__))
class shared_cpu_affinity_config final
{
public:
   shared_cpu_affinity_config() = delete;
   [[maybe_unused, nodiscard]] constexpr shared_cpu_affinity_config(shared_cpu_affinity_config &&rhs) noexcept = default;
   [[maybe_unused, nodiscard]] constexpr shared_cpu_affinity_config(shared_cpu_affinity_config const &rhs) noexcept = default;

   [[maybe_unused, nodiscard]] constexpr explicit shared_cpu_affinity_config(int const ioRing) noexcept :
      m_ioRing{ioRing,}
   {}

   [[maybe_unused]] constexpr shared_cpu_affinity_config &operator = (shared_cpu_affinity_config &&rhs) noexcept = default;
   [[maybe_unused]] constexpr shared_cpu_affinity_config &operator = (shared_cpu_affinity_config const &rhs) noexcept = default;

   [[maybe_unused, nodiscard]] constexpr int io_ring() const noexcept
   {
      return m_ioRing;
   }

private:
   int m_ioRing;
};

using cpu_affinity_config_variant = std::variant<std::nullopt_t, cpu_affinity_config, shared_cpu_affinity_config>;
#else
using shared_cpu_affinity_config = std::nullopt_t;
#endif

class thread_config final
{
public:
   thread_config() = delete;
   [[maybe_unused, nodiscard]] thread_config(thread_config &&rhs) noexcept = default;
   [[maybe_unused, nodiscard]] thread_config(thread_config const &rhs) noexcept = default;
   [[nodiscard]] thread_config(size_t descriptorListCapacity, size_t ioBufferCapacity) noexcept;

   [[maybe_unused]] thread_config &operator = (thread_config &&rhs) noexcept = default;
   [[maybe_unused]] thread_config &operator = (thread_config const &rhs) noexcept = default;

   [[maybe_unused, nodiscard]] size_t descriptor_list_capacity() const noexcept
   {
      return m_descriptorListCapacity;
   }

   [[maybe_unused, nodiscard]] size_t io_buffer_capacity() const noexcept
   {
      return m_ioBufferCapacity;
   }

   [[maybe_unused, nodiscard]] std::optional<cpu_id> worker_cpu_affinity() const noexcept
   {
      return m_workerCpuAffinity;
   }

#if (defined(__linux__))
   [[nodiscard]] cpu_affinity_config_variant const &io_threads_affinity() const noexcept
   {
      return m_ioThreadsAffinity;
   }
#endif

   [[nodiscard]] thread_config with_io_threads_affinity(cpu_affinity_config cpuAffinity) const noexcept;
   [[nodiscard]] thread_config with_io_threads_affinity(shared_cpu_affinity_config cpuAffinity) const noexcept;
   [[nodiscard]] thread_config with_worker_cpu_affinity(cpu_id const value) const noexcept;

private:
   size_t m_descriptorListCapacity;
   size_t m_ioBufferCapacity;
   std::optional<cpu_id> m_workerCpuAffinity{std::nullopt,};
#if (defined(__linux__))
   cpu_affinity_config_variant m_ioThreadsAffinity{std::nullopt,};
#endif
};

}
