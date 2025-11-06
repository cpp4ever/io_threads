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
#include "linux/file_descriptor.hpp" ///< for io_threads::file_descriptor, io_threads::registered_buffer
#include "linux/uring_listener.hpp" ///< for io_threads::uring_listener

#include <sys/types.h> ///< for mode_t

#include <cstddef> ///< for size_t
#include <cstdint> ///< for int32_t, uint32_t
#include <memory> ///< for std::unique_ptr

namespace io_threads
{

class file_writer_uring
{
public:
   file_writer_uring(file_writer_uring &&) = delete;
   file_writer_uring(file_writer_uring const &) = delete;
   virtual ~file_writer_uring() = default;

   file_writer_uring &operator = (file_writer_uring &&) = delete;
   file_writer_uring &operator = (file_writer_uring const &) = delete;

   virtual void prep_close(file_descriptor &fileDescriptor) = 0;
   virtual void prep_fsync(file_descriptor &fileDescriptor) = 0;
   virtual void prep_open(file_descriptor &fileDescriptor, int32_t flags, mode_t mode) = 0;
   virtual void prep_write(file_descriptor &fileDescriptor, uint32_t bytesLength) = 0;

   [[nodiscard]] virtual registered_buffer *register_buffers(uint32_t fileListCapacity, size_t registeredBufferCapacity) = 0;
   [[nodiscard]] virtual file_descriptor *register_file_descriptors(uint32_t fileListCapacity) = 0;
   [[nodiscard]] virtual size_t registered_buffer_capacity(registered_buffer &registeredBuffer) const = 0;
   virtual void unregister_buffers(registered_buffer *registeredBuffers) = 0;
   virtual void unregister_file_descriptors(file_descriptor *fileDescriptors) = 0;

   virtual void run(uring_listener &uringListener) = 0;
   virtual void stop() = 0;
   virtual void wake() = 0;

   [[nodiscard]] virtual shared_cpu_affinity_config share_io_threads() const noexcept = 0;

   [[nodiscard]] static std::unique_ptr<file_writer_uring> construct(cpu_affinity_config_variant const &ioThreadsAffinity, size_t ioRingQueueCapacity);

protected:
   [[nodiscard]] file_writer_uring() noexcept = default;
};

}
