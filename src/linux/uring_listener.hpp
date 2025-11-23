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

#include <cstdint> ///< for int32_t, intptr_t, uint32_t

namespace io_threads
{

class uring_listener
{
public:
   uring_listener(uring_listener &&) = delete;
   uring_listener(uring_listener const &) = delete;
   virtual ~uring_listener() = default;

   uring_listener &operator = (uring_listener &&) = delete;
   uring_listener &operator = (uring_listener const &) = delete;

   virtual void handle_command(intptr_t commandId, intptr_t commandTarget) = 0;

   virtual void handle_event_completion() = 0;
   virtual void handle_task_completion(intptr_t userdata, int32_t result, uint32_t flags) = 0;

protected:
   [[nodiscard]] uring_listener() noexcept = default;
};

}
