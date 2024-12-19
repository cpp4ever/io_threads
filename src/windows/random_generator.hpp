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

#include "common/logger.hpp" ///< for io_threads::log_system_error
#include "common/utility.hpp" ///< for io_threads::unreachable

#include <Windows.h> ///< for bcrypt.h, PUCHAR, ULONG
/// for
///   BCRYPT_ALG_HANDLE,
///   BCRYPT_RNG_ALGORITHM,
///   BCryptCloseAlgorithmProvider,
///   BCryptGenRandom,
///   BCryptOpenAlgorithmProvider
#include <bcrypt.h>
#include <SubAuth.h> ///< for STATUS_SUCCESS

#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <cstddef> ///< for size_t, std::byte
#include <memory> ///< for std::addressof

#pragma comment(lib, "bcrypt")

namespace io_threads
{

class random_algorithm_provider final
{
public:
   [[nodiscard]] random_algorithm_provider()
   {
      if (
         auto const returnCode{BCryptOpenAlgorithmProvider(std::addressof(m_algorithmHandle), BCRYPT_RNG_ALGORITHM, nullptr, 0),};
         STATUS_SUCCESS != returnCode
      ) [[unlikely]]
      {
         log_system_error("[random] failed to open algorithm provider: ({}) - {}", returnCode);
         unreachable();
      }
   }

   random_algorithm_provider(random_algorithm_provider &&) = delete;
   random_algorithm_provider(random_algorithm_provider const &) = delete;

   ~random_algorithm_provider()
   {
      if (auto const returnCode{BCryptCloseAlgorithmProvider(m_algorithmHandle, 0),}; STATUS_SUCCESS != returnCode) [[unlikely]]
      {
         log_system_error("[random] failed to close algorithm provider: ({}) - {}", returnCode);
      }
   }

   random_algorithm_provider &operator = (random_algorithm_provider &&) = delete;
   random_algorithm_provider &operator = (random_algorithm_provider const &) = delete;

   [[nodiscard]] BCRYPT_ALG_HANDLE algorithm_handle() const noexcept
   {
      return m_algorithmHandle;
   }

private:
   BCRYPT_ALG_HANDLE m_algorithmHandle{nullptr};
};

class random_generator final
{
public:
   [[nodiscard]] random_generator() = default;
   random_generator(random_generator &&) = delete;
   random_generator(random_generator const &) = delete;

   random_generator &operator = (random_generator &&) = delete;
   random_generator &operator = (random_generator const &) = delete;

   static void generate(std::byte *bytes, size_t const bytesLength)
   {
      assert(nullptr != bytes);
      assert(0 < bytesLength);
      if (
         auto const returnCode{BCryptGenRandom(provider.algorithm_handle(), std::bit_cast<PUCHAR>(bytes), static_cast<ULONG>(bytesLength), 0),};
         STATUS_SUCCESS != returnCode
      ) [[unlikely]]
      {
         log_system_error("[random] failed to generate random sequence: ({}) - {}", returnCode);
         unreachable();
      }
   }

private:
   static inline random_algorithm_provider provider{};
};

}
