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

#include "common/utility.hpp" ///< for io_threads::unreachable
#include "openssl/error.hpp" ///< for io_threads::log_openssl_errors

#include <openssl/evp.h>

#include <array> ///< for std::array
#include <bit> ///< for std::bit_cast
#include <cstddef> ///< for size_t, std::byte
#include <memory> ///< for std::addressof
#include <new> ///< for operator delete, operator new, std::align_val_t
#include <source_location> ///< for std::source_location

namespace io_threads
{

constexpr size_t sha1_digest_size = 20;
using sha1_digest = std::array<std::byte, sha1_digest_size>;

class sha1_context final
{
public:
   [[nodiscard]] sha1_context()
   {
      m_digestMethod = EVP_MD_fetch(nullptr, "SHA1", nullptr);
      if (nullptr == m_digestMethod) [[unlikely]]
      {
         log_openssl_errors("[sha1] failed to fetch digest method");
         unreachable();
      }
      m_digestMethodContext = EVP_MD_CTX_new();
      if (nullptr == m_digestMethodContext) [[unlikely]]
      {
         log_openssl_errors("[sha1] failed to create digest method context");
         unreachable();
      }
      init();
   }

   sha1_context(sha1_context &&) = delete;
   sha1_context(sha1_context const &) = delete;

   ~sha1_context()
   {
      EVP_MD_CTX_free(m_digestMethodContext);
      EVP_MD_free(m_digestMethod);
   }

   sha1_context &operator = (sha1_context &&) = delete;
   sha1_context &operator = (sha1_context const &) = delete;

   [[nodiscard]] sha1_digest finish()
   {
      sha1_digest digest{};
      uint32_t digestSize{0,};
      if (0 == EVP_DigestFinal(m_digestMethodContext, std::bit_cast<uint8_t *>(digest.data()), std::addressof(digestSize))) [[unlikely]]
      {
         log_openssl_errors("[sha1] failed to finalize digest");
         unreachable();
      }
      assert(digestSize == digest.size());
      init();
      return digest;
   }

   void update(std::byte const *bytes, size_t const bytesLength)
   {
      if (0 == EVP_DigestUpdate(m_digestMethodContext, bytes, bytesLength)) [[unlikely]]
      {
         log_openssl_errors("[sha1] failed to update digest");
         unreachable();
      }
   }

private:
   EVP_MD *m_digestMethod{nullptr,};
   EVP_MD_CTX *m_digestMethodContext{nullptr,};

   void init()
   {
      if (0 == EVP_DigestInit(m_digestMethodContext, m_digestMethod)) [[unlikely]]
      {
         log_openssl_errors("[sha1] failed to initialize digest method context");
         unreachable();
      }
   }
};

}
