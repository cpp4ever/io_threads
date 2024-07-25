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

#include "io_threads/tcp_client_config.hpp" ///< for io_threads::tcp_client_config
#include "io_threads/tcp_client_thread.hpp" ///< for io_threads::tcp_client_thread

#include <cstddef> ///< for size_t, std::byte
#include <memory> ///< for std::shared_ptr
#include <system_error> ///< for std::error_code

namespace io_threads
{

struct tcp_socket_descriptor;

class tcp_client_thread::tcp_client
{
public:
   class tcp_client_thread_worker;

   tcp_client() = delete;
   tcp_client(tcp_client &&) = delete;
   tcp_client(tcp_client const &) = delete;
   [[nodiscard]] explicit tcp_client(tcp_client_thread const &tcpClientThread);
   virtual ~tcp_client();

   tcp_client &operator = (tcp_client &&) = delete;
   tcp_client &operator = (tcp_client const &) = delete;

protected:
   void ready_to_connect();
   void ready_to_disconnect();
   void ready_to_send();

private:
   std::shared_ptr<tcp_client_thread::tcp_client_thread_impl> const m_thread;
   tcp_socket_descriptor *m_socketDescriptor = nullptr;

   virtual void io_connected() = 0;
   virtual size_t io_data_to_send(std::byte *bytes, size_t bytesCapacity) = 0;
   virtual size_t io_data_to_shutdown(std::byte *bytes, size_t bytesCapacity) = 0;
   virtual size_t io_data_received(std::byte const *bytes, size_t bytesLength) = 0;
   virtual void io_disconnected(std::error_code errorCode) = 0;

   virtual std::error_code io_last_error() const
   {
      return std::error_code{};
   }

   virtual tcp_client_config io_ready_to_connect() = 0;
};

using tcp_client = tcp_client_thread::tcp_client;

}
