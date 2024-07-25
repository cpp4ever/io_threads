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
#if (defined(IO_THREADS_OPENSSL))
#include "io_threads/tls_client.hpp" ///< for io_threads::make_x509_error_code
#include "openssl/error.hpp" ///< for io_threads::log_openssl_errors

#include <openssl/err.h> ///< for ERR_get_error_all, ERR_GET_LIB, ERR_TXT_STRING
#include <openssl/ssl.h>

#include <cassert> ///< for assert
#include <cstdint> ///< for uint32_t
#include <format> ///< for std::format
#include <ios> ///< for std::dec, std::hex
#include <iostream> ///< for std::cerr
#include <memory> ///< for std::addressof
#include <ostream> ///< for std::endl
#include <source_location> ///< for std::source_location
#include <syncstream> ///< for std::osyncstream
#include <sstream> ///< for std::stringstream
#include <string_view> ///< for std::string_view

namespace io_threads
{

void log_openssl_errors(std::string_view const &prefix, std::source_location const &sourceLocation)
{
   std::stringstream sink{};
   unsigned long errorCode{0,};
   char const *errorLocationFilePath{"",};
   int errorLocationFileLine{0,};
   char const *errorLocationFunctionName{"",};
   char const *errorData{"",};
   int errorFlags{0,};
   while (
      (
         errorCode = ERR_get_error_all(
            std::addressof(errorLocationFilePath),
            std::addressof(errorLocationFileLine),
            std::addressof(errorLocationFunctionName),
            std::addressof(errorData),
            std::addressof(errorFlags)
         )
      ) != 0
   )
   {
      sink << std::endl << "\t[";
      if (auto const *libraryName{ERR_lib_error_string(errorCode),}; nullptr == libraryName)
      {
         sink << "lib(" << static_cast<uint32_t>(ERR_GET_LIB(errorCode)) << ")";
      }
      else
      {
         sink << libraryName;
      }
      sink << "@" << errorLocationFilePath << ":" << errorLocationFunctionName << ":" << errorLocationFileLine << "] ";
      if (auto const *errorReason{ERR_reason_error_string(errorCode),}; nullptr == errorReason)
      {
         sink << "reason(" << static_cast<uint32_t>(ERR_GET_REASON(errorCode)) << ")";
      }
      else
      {
         sink << errorReason;
      }
      sink << ": (" << std::hex << errorCode << std::dec << ")";
      if (
         true
         && (nullptr != errorData)
         && (0 != errorData[0])
         && (ERR_TXT_STRING == (ERR_TXT_STRING & errorFlags))
      )
      {
         sink << " - " << errorData;
      }
   }
   std::osyncstream{std::cerr,}
      << sourceLocation.file_name()
      << ":" << sourceLocation.line()
      << " " << prefix
      << sink.str()
      << std::endl
   ;
}

namespace
{

struct openssl_error_category final
{
private:
   class openssl_error_category_impl final : public std::error_category
   {
   public:
      [[nodiscard]] constexpr openssl_error_category_impl() noexcept = default;
      openssl_error_category_impl(openssl_error_category_impl &&) = delete;
      openssl_error_category_impl(openssl_error_category_impl const &) = delete;

      openssl_error_category_impl &operator = (openssl_error_category_impl &&) = delete;
      openssl_error_category_impl &operator = (openssl_error_category_impl const &) = delete;

      [[nodiscard]] const char *name() const noexcept override
      {
         return "openssl";
      }

      [[nodiscard]] std::string message(int const value) const override
      {
         auto const *errorReason{ERR_reason_error_string(value),};
         return (nullptr == errorReason)
            ? std::format("reason({})", static_cast<uint32_t>(ERR_GET_REASON(value)))
            : std::string{errorReason,}
         ;
      }
   };

   static inline openssl_error_category_impl impl{};

public:
   [[nodiscard]] static std::error_category const &instance() noexcept
   {
      return impl;
   }
};

struct ssl_error_category final
{
private:
   class ssl_error_category_impl final : public std::error_category
   {
   public:
      [[nodiscard]] constexpr ssl_error_category_impl() noexcept = default;
      ssl_error_category_impl(ssl_error_category_impl &&) = delete;
      ssl_error_category_impl(ssl_error_category_impl const &) = delete;

      ssl_error_category_impl &operator = (ssl_error_category_impl &&) = delete;
      ssl_error_category_impl &operator = (ssl_error_category_impl const &) = delete;

      [[nodiscard]] const char *name() const noexcept override
      {
         return "ssl";
      }

      [[nodiscard]] std::string message(int const) const override
      {
         return "unhandled error";
      }
   };

   static inline ssl_error_category_impl impl{};

public:
   [[nodiscard]] static std::error_category const &instance() noexcept
   {
      return impl;
   }
};

struct x509_error_category final
{
private:
   class x509_error_category_impl final : public std::error_category
   {
   public:
      [[nodiscard]] constexpr x509_error_category_impl() noexcept = default;
      x509_error_category_impl(x509_error_category_impl &&) = delete;
      x509_error_category_impl(x509_error_category_impl const &) = delete;

      x509_error_category_impl &operator = (x509_error_category_impl &&) = delete;
      x509_error_category_impl &operator = (x509_error_category_impl const &) = delete;

      [[nodiscard]] const char *name() const noexcept override
      {
         return "x509";
      }

      [[nodiscard]] std::string message(int const value) const override
      {
         return X509_verify_cert_error_string(value);
      }
   };

   static inline x509_error_category_impl impl{};

public:
   [[nodiscard]] static std::error_category const &instance() noexcept
   {
      return impl;
   }
};

}

std::error_code make_ssl_error_code(int const value)
{
   return std::error_code{value, ssl_error_category::instance(),};
}

std::error_code make_ssl_error_code(SSL &ssl, int const returnCode)
{
   auto const value{SSL_get_error(std::addressof(ssl), returnCode),};
   if (SSL_ERROR_NONE == value) [[likely]]
   {
      return std::error_code{};
   }
   auto const errorCode{ERR_peek_last_error(),};
   if ((SSL_ERROR_SSL == value) && (ERR_LIB_SSL == ERR_GET_LIB(errorCode)) && (SSL_R_CERTIFICATE_VERIFY_FAILED == ERR_GET_REASON(errorCode)))
   {
      if (auto const verifyResult{SSL_get_verify_result(std::addressof(ssl)),}; X509_V_OK != verifyResult)
      {
         return make_x509_error_code(static_cast<int>(verifyResult));
      }
   }
   if ((SSL_ERROR_SSL == value) || (SSL_ERROR_SYSCALL == value))
   {
      return make_tls_error_code(static_cast<int>(errorCode));
   }
   return make_ssl_error_code(value);
}

std::error_code make_tls_error_code(int const value)
{
   return std::error_code{value, openssl_error_category::instance(),};
}

std::error_code make_x509_error_code(int const value)
{
   return std::error_code{value, x509_error_category::instance(),};
}

}
#endif
