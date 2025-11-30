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

#include "common/websocket_client_handshake_response_parser.hpp" ///< for io_threads::websocket_client_handshake_response_parser
#include "common/websocket_client_session.hpp" ///< for io_threads::websocket_client_session
#include "io_threads/data_chunk.hpp" ///< for io_threads::data_chunk
#include "io_threads/websocket_client_config.hpp" ///< for io_threads::websocket_client_config
#if (defined(__linux__))
#  include "linux/random_generator.hpp" ///< for io_threads::random_generator
#elif (defined(_WIN32) || defined(_WIN64))
#  include "windows/random_generator.hpp" ///< for io_threads::random_generator
#endif
#if (defined(IO_THREADS_OPENSSL))
#  include "openssl/sha1.hpp" ///< for io_threads::sha1_context
#elif (defined(IO_THREADS_SCHANNEL))
#  include "windows/sha1.hpp" ///< for io_threads::sha1_context
#endif

#include <cstddef> ///< for size_t
#include <string_view> ///< for std::string_view
#include <system_error> ///< for std::error_code

namespace io_threads
{

class websocket_client_handshake_handler final
{
public:
   [[nodiscard]] websocket_client_handshake_handler() = default;
   websocket_client_handshake_handler(websocket_client_handshake_handler &&) = delete;
   websocket_client_handshake_handler(websocket_client_handshake_handler const &) = delete;

   websocket_client_handshake_handler &operator = (websocket_client_handshake_handler &&) = delete;
   websocket_client_handshake_handler &operator = (websocket_client_handshake_handler const &) = delete;

   [[nodiscard]] size_t build_request(
      websocket_client_session &session,
      data_chunk const &dataChunk,
      websocket_client_config const &config,
      std::string_view const &host
   );

   [[nodiscard]] std::error_code handle_response(websocket_client_session &session, std::string_view const &handshakeResponse);

private:
   random_generator m_randomGenerator{};
   sha1_context m_sha1Context{};
   websocket_client_handshake_response_parser m_responseParser{};
};

}
