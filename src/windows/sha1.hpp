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

#include "common/logger.hpp" ///< for io_threads::log_error, io_threads::log_system_error
#include "common/utility.hpp" ///< for io_threads::unreachable

#include <Windows.h> ///< for bcrypt.h, DWORD, PUCHAR, ULONG
/// for
///   BCRYPT_ALG_HANDLE,
///   BCRYPT_HASH_HANDLE,
///   BCRYPT_HASH_LENGTH,
///   BCRYPT_HASH_REUSABLE_FLAG,
///   BCRYPT_OBJECT_LENGTH,
///   BCRYPT_SHA1_ALGORITHM,
///   BCryptCloseAlgorithmProvider,
///   BCryptCreateHash,
///   BCryptDestroyHash,
///   BCryptFinishHash,
///   BCryptGetProperty,
///   BCryptHashData,
///   BCryptOpenAlgorithmProvider
#include <bcrypt.h>
#include <SubAuth.h> ///< for STATUS_SUCCESS

#include <array> ///< for std::array
#include <bit> ///< for std::bit_cast
#include <cstddef> ///< for size_t, std::byte
#include <memory> ///< for std::addressof
#include <new> ///< for operator delete, operator new, std::align_val_t
#include <source_location> ///< for std::source_location

#pragma comment(lib, "bcrypt")

namespace io_threads
{

constexpr size_t sha1_digest_size = 20;
using sha1_digest = std::array<std::byte, sha1_digest_size>;

class sha1_provider final
{
public:
   [[nodiscard]] sha1_provider()
   {
      if (
         auto const returnCode{BCryptOpenAlgorithmProvider(std::addressof(m_algorithmHandle), BCRYPT_SHA1_ALGORITHM, nullptr, BCRYPT_HASH_REUSABLE_FLAG),};
         STATUS_SUCCESS != returnCode
      ) [[unlikely]]
      {
         log_system_error("[sha1] failed to open algorithm provider: ({}) - {}", returnCode);
         unreachable();
      }
      ULONG bytesWritten{0,};
      if (
         auto const returnCode
         {
            BCryptGetProperty(
               m_algorithmHandle,
               BCRYPT_OBJECT_LENGTH,
               std::bit_cast<PUCHAR>(std::addressof(m_objectSize)),
               sizeof(m_objectSize),
               std::addressof(bytesWritten),
               0
            ),
         };
         STATUS_SUCCESS != returnCode
      ) [[unlikely]]
      {
         log_system_error("[sha1] failed to get size of hash object: ({}) - {}", returnCode);
         unreachable();
      }
      assert(sizeof(m_objectSize) == bytesWritten);
      DWORD digestSize{0,};
      if (
         auto const returnCode
         {
            BCryptGetProperty(
               m_algorithmHandle,
               BCRYPT_HASH_LENGTH,
               std::bit_cast<PUCHAR>(std::addressof(digestSize)),
               sizeof(digestSize),
               std::addressof(bytesWritten),
               0
            ),
         };
         STATUS_SUCCESS != returnCode
      ) [[unlikely]]
      {
         log_system_error("[sha1] failed to get digest size: ({}) - {}", returnCode);
         unreachable();
      }
      assert(sizeof(digestSize) == bytesWritten);
      if (sha1_digest_size != digestSize) [[unlikely]]
      {
         log_error(std::source_location::current(), "[sha1] wrong digest size {} bytes, expected {} bytes", digestSize, sha1_digest_size);
         unreachable();
      }
   }

   sha1_provider(sha1_provider &&) = delete;
   sha1_provider(sha1_provider const &) = delete;

   ~sha1_provider()
   {
      if (auto const returnCode{BCryptCloseAlgorithmProvider(m_algorithmHandle, 0),}; STATUS_SUCCESS != returnCode) [[unlikely]]
      {
         log_system_error("[sha1] failed to close algorithm provider: ({}) - {}", returnCode);
      }
   }

   sha1_provider &operator = (sha1_provider &&) = delete;
   sha1_provider &operator = (sha1_provider const &) = delete;

   [[nodiscard]] BCRYPT_HASH_HANDLE &new_handle() const
   {
      auto *hashHandle = std::bit_cast<BCRYPT_HASH_HANDLE *>(
         ::operator new(sizeof(BCRYPT_HASH_HANDLE) + m_objectSize, std::align_val_t{alignof(BCRYPT_HASH_HANDLE),})
      );
      if (
         auto const returnCode
         {
            BCryptCreateHash(
               m_algorithmHandle,
               hashHandle,
               std::bit_cast<PUCHAR>(hashHandle + 1),
               m_objectSize,
               nullptr,
               0,
               0
            ),
         };
         STATUS_SUCCESS != returnCode
      ) [[unlikely]]
      {
         log_system_error("[sha1] failed to create hash object: ({}) - {}", returnCode);
         unreachable();
      }
      return *hashHandle;
   }

   static void free_handle(BCRYPT_HASH_HANDLE &hashHandle)
   {
      if (auto const returnCode{BCryptDestroyHash(hashHandle),}; STATUS_SUCCESS != returnCode) [[unlikely]]
      {
         log_system_error("[sha1] failed to destroy hash object: ({}) - {}", returnCode);
      }
      ::operator delete(std::addressof(hashHandle), std::align_val_t{alignof(BCRYPT_HASH_HANDLE),});
   }

private:
   BCRYPT_ALG_HANDLE m_algorithmHandle{nullptr,};
   DWORD m_objectSize{0,};
};

class sha1_context final
{
public:
   [[nodiscard]] sha1_context() = default;
   sha1_context(sha1_context &&) = delete;
   sha1_context(sha1_context const &) = delete;

   ~sha1_context()
   {
      provider.free_handle(m_hashHandle);
   }

   sha1_context &operator = (sha1_context &&) = delete;
   sha1_context &operator = (sha1_context const &) = delete;

   [[nodiscard]] sha1_digest finish() const
   {
      sha1_digest digest{};
      if (
         auto const returnCode{BCryptFinishHash(m_hashHandle, std::bit_cast<PUCHAR>(digest.data()), static_cast<ULONG>(digest.size()), 0),};
         STATUS_SUCCESS != returnCode
      ) [[unlikely]]
      {
         log_system_error("[sha1] failed to finish the hash: ({}) - {}", returnCode);
         unreachable();
      }
      return digest;
   }

   void update(std::byte const *bytes, size_t const bytesLength)
   {
      if (
         auto const returnCode{BCryptHashData(m_hashHandle, std::bit_cast<PUCHAR>(bytes), static_cast<ULONG>(bytesLength), 0),};
         STATUS_SUCCESS != returnCode
      ) [[unlikely]]
      {
         log_system_error("[sha1] failed to update the hash: ({}) - {}", returnCode);
         unreachable();
      }
   }

private:
   BCRYPT_HASH_HANDLE &m_hashHandle{provider.new_handle(),};

   static inline sha1_provider provider{};
};

}
