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

#include "common/sec_websocket_key.hpp" ///< for io_threads::sec_websocket_key
#if (defined(IO_THREADS_OPENSSL))
#  include "openssl/base64.hpp" ///< for io_threads::base64_encode
#elif (defined(IO_THREADS_SCHANNEL))
#  include "windows/base64.hpp" ///< for io_threads::base64_encode
#endif
#if (defined(__linux__))
#  include "linux/random_generator.hpp" ///< for io_threads::random_generator
#elif (defined(_WIN32) || defined(_WIN64))
#  include "windows/random_generator.hpp" ///< for io_threads::random_generator
#endif

#include <array> ///< for std::array
#include <bit> ///< for std::bit_cast
#include <cstddef> ///< for std::byte
#include <string_view> ///< for std::string_view

namespace io_threads
{

std::string_view build_sec_websocket_key(sec_websocket_key &secWebSocketKey, random_generator &randomGenerator)
{
   std::array<std::byte, sec_websocket_key::sizeof_value> handshakeKey{std::byte{0,}};
   randomGenerator.generate(handshakeKey.data(), handshakeKey.size());
   secWebSocketKey.bytesLength = base64_encode(secWebSocketKey.bytes, handshakeKey);
   return std::string_view{std::bit_cast<char const *>(secWebSocketKey.bytes.data()), secWebSocketKey.bytesLength,};
}

}
