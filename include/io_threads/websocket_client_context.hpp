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
#include <memory> ///< for std::shared_ptr

namespace io_threads
{

class websocket_client_context final
{
public:
   class wss_client;

   websocket_client_context() = delete;
   [[nodiscard]] websocket_client_context(websocket_client_context &&rhs) noexcept;
   [[nodiscard]] websocket_client_context(websocket_client_context const &rhs) noexcept;
   [[nodiscard]] websocket_client_context(
      size_t inboundBufferListCapacity,
      size_t inboundBufferCapacity,
      size_t outboundBufferListCapacity,
      size_t outboundBufferCapacity
   );
   ~websocket_client_context();

   websocket_client_context &operator = (websocket_client_context &&rhs) noexcept;
   websocket_client_context &operator = (websocket_client_context const &rhs);

private:
   class websocket_client_context_impl;

   std::shared_ptr<websocket_client_context_impl> m_impl;
};

}
