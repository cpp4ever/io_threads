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

#include "io_threads/tls_client.hpp" ///< for io_threads::tls_client
#include "io_threads/tls_client_context.hpp" ///< for io_threads::tls_client_context
#include "io_threads/websocket_client_config.hpp" ///< for io_threads::websocket_client_config
#include "io_threads/websocket_frame.hpp" ///< for io_threads::websocket_frame
#include "io_threads/wss_client_context.hpp" ///< for io_threads::wss_client_context

#include <cstddef> ///< for size_t
#include <memory> ///< for std::shared_ptr
#include <system_error> ///< for std::error_code

namespace io_threads
{

struct websocket_client_session;

class wss_client_context::wss_client : public tls_client
{
private:
   using super = tls_client;

public:
   wss_client() = delete;
   wss_client(wss_client &&) = delete;
   wss_client(wss_client const &) = delete;
   [[nodiscard]] explicit wss_client(wss_client_context wssClientContext) noexcept;
   ~wss_client() override;

   wss_client &operator = (wss_client &&) = delete;
   wss_client &operator = (wss_client const &) = delete;

   [[maybe_unused, nodiscard]] wss_client_context const &context() const noexcept
   {
      return m_wssClientContext;
   }

protected:
   void io_connected() override;
   void io_disconnected(std::error_code const &errorCode) override;

   void ready_to_close();

private:
   wss_client_context const m_wssClientContext;
   websocket_client_session *m_websocketClientSession{nullptr};

   [[nodiscard]] std::error_code io_data_decrypted(data_chunk const &dataChunk) final;
   [[nodiscard]] std::error_code io_data_to_encrypt(data_chunk const &dataChunk, size_t &bytesWritten) final;
   [[nodiscard]] virtual std::error_code io_frame_received(websocket_frame const &dataFrame, bool finalFrame) = 0;
   [[nodiscard]] virtual websocket_frame io_frame_to_send() = 0;
   [[nodiscard]] std::error_code io_handle_frame(data_chunk const &dataChunk);
   [[nodiscard]] virtual websocket_client_config io_ready_to_handshake() = 0;
};

using wss_client [[maybe_unused]] = wss_client_context::wss_client;

}
