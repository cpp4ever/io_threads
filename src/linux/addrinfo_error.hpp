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

#include <errno.h> ///< for errno
#include <netdb.h> ///< for EAI_SYSTEM, gai_strerror

#include <system_error> ///< for std::error_category, std::error_code, std::generic_category

namespace io_threads
{

struct addrinfo_error_category final
{
private:
   class addrinfo_error_category_impl final : public std::error_category
   {
   public:
      [[nodiscard]] constexpr addrinfo_error_category_impl() noexcept = default;
      addrinfo_error_category_impl(addrinfo_error_category_impl &&) = delete;
      addrinfo_error_category_impl(addrinfo_error_category_impl const &) = delete;

      addrinfo_error_category_impl &operator = (addrinfo_error_category_impl &&) = delete;
      addrinfo_error_category_impl &operator = (addrinfo_error_category_impl const &) = delete;

      [[nodiscard]] const char *name() const noexcept override
      {
         return "addrinfo";
      }

      [[nodiscard]] std::string message(int const value) const override
      {
         return gai_strerror(value);
      }
   };

   static inline addrinfo_error_category_impl impl{};

public:
   [[nodiscard]] static std::error_category const &instance() noexcept
   {
      return impl;
   }
};

[[nodiscard]] inline std::error_code make_addrinfo_error_code(int const value) noexcept
{
   return (EAI_SYSTEM == value)
      ? std::error_code{errno, std::generic_category(),}
      : std::error_code{value, addrinfo_error_category::instance(),}
   ;
}

}
