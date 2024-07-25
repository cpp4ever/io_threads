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

#include "common/sec_websocket_accept.hpp" ///< for io_threads::sec_websocket_accept
#include "common/sec_websocket_key.hpp" ///< for io_threads::sec_websocket_key
#if (defined(IO_THREADS_OPENSSL))
#  include "openssl/base64.hpp" ///< for io_threads::base64_encode
#  include "openssl/sha1.hpp" ///< for io_threads::sha1_context
#elif (defined(IO_THREADS_SCHANNEL))
#  include "windows/base64.hpp" ///< for io_threads::base64_encode
#  include "windows/sha1.hpp" ///< for io_threads::sha1_context
#endif

#include <bit> ///< for std::bit_cast
#include <cstddef> ///< for std::byte
#include <string_view> ///< for std::string_view

namespace io_threads
{

sec_websocket_accept make_sec_websocket_accept(sec_websocket_key const &secWebSocketKey, sha1_context &sha1Context)
{
   sha1Context.update(secWebSocketKey.bytes.data(), secWebSocketKey.bytesLength);
   constexpr std::string_view handshakeUuid{"258EAFA5-E914-47DA-95CA-C5AB0DC85B11",};
   sha1Context.update(std::bit_cast<std::byte const *>(handshakeUuid.data()), handshakeUuid.size());
   auto handshakeKeySha1Digest{sha1Context.finish(),};
   sec_websocket_accept secWebSocketAccept{};
   secWebSocketAccept.bytesLength = base64_encode(secWebSocketAccept.bytes, handshakeKeySha1Digest);
   return secWebSocketAccept;
}

}
