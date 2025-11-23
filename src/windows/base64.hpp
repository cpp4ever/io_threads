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

#include <Windows.h> ///< for BYTE, DWORD, LPSTR, TRUE, wincrypt.h
#include <wincrypt.h> ///< for CRYPT_STRING_BASE64, CRYPT_STRING_NOCRLF, CryptBinaryToStringA

#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <cstdint> ///< for uint32_t
#include <memory> ///< for std::addressof
#include <system_error> ///< for std::error_code

#pragma comment(lib, "Crypt32")

namespace io_threads
{

template<typename string_output, typename binary_input>
[[nodiscard]] uint32_t base64_encode(string_output &stringOutput, binary_input const &binaryInput)
{
   assert((4 * (std::size(binaryInput) + 2) / 3 + 1) <= std::size(stringOutput));
   auto const inputBytesLength{static_cast<DWORD>(std::size(binaryInput)),};
   auto outputBytesLength{static_cast<DWORD>(std::size(stringOutput)),};
   [[maybe_unused]] auto const returnCode = CryptBinaryToStringA(
      std::bit_cast<BYTE const *>(std::data(binaryInput)),
      inputBytesLength,
      CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
      std::bit_cast<LPSTR>(std::data(stringOutput)),
      std::addressof(outputBytesLength)
   );
   assert(TRUE == returnCode);
   return outputBytesLength;
}

}
