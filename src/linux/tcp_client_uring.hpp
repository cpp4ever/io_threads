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

#include "io_threads/thread_config.hpp" ///< for io_threads::cpu_affinity_config_variant
#include "linux/tcp_socket_descriptor.hpp" ///< for io_threads::tcp_socket_descriptor
#include "linux/tcp_socket_operation.hpp" ///< for io_threads::tcp_socket_operation
#include "linux/uring_listener.hpp" ///< for io_threads::uring_listener

#include <liburing/io_uring_version.h> ///< for IO_URING_VERSION_MAJOR, IO_URING_VERSION_MINOR
#include <linux/time_types.h> ///< for __kernel_timespec
#include <sys/socket.h> ///< for sa_family_t, sockaddr

#include <cstddef> ///< for size_t
#include <cstdint> ///< for int32_t, uint32_t
#include <memory> ///< for std::unique_ptr

namespace io_threads
{

class tcp_client_uring
{
public:
   tcp_client_uring(tcp_client_uring &&) = delete;
   tcp_client_uring(tcp_client_uring const &) = delete;
   virtual ~tcp_client_uring() = default;

   tcp_client_uring &operator = (tcp_client_uring &&) = delete;
   tcp_client_uring &operator = (tcp_client_uring const &) = delete;

   virtual void prep_close(tcp_socket_operation &tcpSocketOperation) = 0;
   virtual void prep_connect(tcp_socket_operation &tcpSocketOperation, sockaddr const &socketAddress) = 0;
   virtual void prep_recv(tcp_socket_operation &tcpSocketOperation) = 0;
   virtual void prep_send(tcp_socket_operation &tcpSocketOperation, size_t bytesLength) = 0;
#if ((2 < IO_URING_VERSION_MAJOR) || ((2 == IO_URING_VERSION_MAJOR) && (6 <= IO_URING_VERSION_MINOR)))
   virtual void prep_setsockopt(
      tcp_socket_operation &tcpSocketOperation,
      int sockoptLevel,
      int sockoptName,
      void *sockoptValue,
      int sockoptValueSize
   ) = 0;
   virtual void prep_setsockopt(
      tcp_socket_operation &tcpSocketOperation,
      int sockoptLevel,
      int sockoptName,
      int sockoptValue
   ) = 0;
#endif
   virtual void prep_shutdown(tcp_socket_operation &tcpSocketOperation, int32_t how) = 0;
   virtual void prep_socket(tcp_socket_operation &tcpSocketOperation, sa_family_t addressFamily) = 0;

   virtual void register_tcp_socket(tcp_socket_descriptor &tcpSocketDescriptor, int32_t tcpSocket) = 0;
   [[nodiscard]] virtual tcp_socket_descriptor *register_tcp_socket_descriptors(uint32_t socketListCapacity) = 0;
   [[nodiscard]] virtual tcp_socket_operation *register_tcp_socket_operations(
      uint32_t socketOperationListCapacity,
      size_t registeredBufferCapacity
   ) = 0;
   [[nodiscard]] virtual size_t registered_buffer_capacity(tcp_socket_operation &tcpSocketOperation) const = 0;
   virtual void unregister_tcp_socket_descriptors(tcp_socket_descriptor *tcpSocketDescriptors) = 0;
   virtual void unregister_tcp_socket_operations(tcp_socket_operation *tcpSocketOperations) = 0;

   [[nodiscard]] virtual intptr_t poll(uring_listener &uringListener, __kernel_timespec *timeout) = 0;
   virtual void stop() = 0;
   virtual void wake() = 0;

   [[nodiscard]] virtual shared_cpu_affinity_config share_io_threads() const noexcept = 0;

   [[nodiscard]] static std::unique_ptr<tcp_client_uring> construct(cpu_affinity_config_variant const &ioThreadsAffinity, size_t ioRingQueueCapacity);

protected:
   [[nodiscard]] tcp_client_uring() noexcept = default;
};

}
