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
#include <cstdint> ///< for uint16_t
#include <functional> ///< for std::function
#include <memory> ///< for std::shared_ptr
#include <optional> ///< for std::nullopt, std::optional

namespace io_threads
{

class tcp_client_thread_config final
{
public:
   tcp_client_thread_config() = delete;
   [[maybe_unused, nodiscard]] tcp_client_thread_config(tcp_client_thread_config &&rhs) noexcept = default;
   [[maybe_unused, nodiscard]] tcp_client_thread_config(tcp_client_thread_config const &rhs) noexcept = default;
   [[nodiscard]] tcp_client_thread_config(size_t socketListCapacity, size_t ioBufferCapacity) noexcept;

   [[maybe_unused]] tcp_client_thread_config &operator = (tcp_client_thread_config &&rhs) noexcept = default;
   [[maybe_unused]] tcp_client_thread_config &operator = (tcp_client_thread_config const &rhs) noexcept = default;

   [[maybe_unused, nodiscard]] size_t io_buffer_capacity() const noexcept
   {
      return m_ioBufferCapacity;
   }

   [[maybe_unused, nodiscard]] std::optional<uint16_t> io_cpu_affinity() const noexcept
   {
      return m_ioCpuAffinity;
   }

   [[maybe_unused, nodiscard]] std::optional<uint16_t> poll_cpu_affinity() const noexcept
   {
      return m_pollCpuAffinity;
   }

   [[maybe_unused, nodiscard]] size_t socket_list_capacity() const noexcept
   {
      return m_socketListCapacity;
   }

   [[nodiscard]] tcp_client_thread_config with_io_cpu_affinity(uint16_t const value) const noexcept;
   [[nodiscard]] tcp_client_thread_config with_poll_cpu_affinity(uint16_t const value) const noexcept;

private:
   size_t m_socketListCapacity;
   size_t m_ioBufferCapacity;
   std::optional<uint16_t> m_pollCpuAffinity{std::nullopt,};
   std::optional<uint16_t> m_ioCpuAffinity{std::nullopt,};
};

class tcp_client_thread final
{
public:
   class tcp_client;

   tcp_client_thread() = delete;
   [[nodiscard]] tcp_client_thread(tcp_client_thread &&rhs) noexcept;
   [[nodiscard]] tcp_client_thread(tcp_client_thread const &rhs) noexcept;
   [[nodiscard]] explicit tcp_client_thread(tcp_client_thread_config const &tcpClientThreadConfig);
   ~tcp_client_thread();

   tcp_client_thread &operator = (tcp_client_thread &&rhs) noexcept;
   tcp_client_thread &operator = (tcp_client_thread const &rhs);

   void execute(std::function<void()> const &ioRoutine) const;

private:
   class tcp_client_thread_impl;

   std::shared_ptr<tcp_client_thread_impl> m_impl;
};

}
