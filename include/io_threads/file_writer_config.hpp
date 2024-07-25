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

#include "io_threads/file_writer_option.hpp" ///< for io_threads::file_writer_option

#include <filesystem> ///< for std::filesystem::path
/// for
///   std::is_nothrow_copy_assignable_v,
///   std::is_nothrow_copy_constructible_v,
///   std::is_nothrow_move_assignable_v,
///   std::is_nothrow_move_constructible_v
#include <type_traits>

namespace io_threads
{

class file_writer_config final
{
public:
   file_writer_config() = delete;
   [[maybe_unused, nodiscard]] file_writer_config(file_writer_config &&rhs) noexcept(true == std::is_nothrow_move_constructible_v<std::filesystem::path>) = default;
   [[maybe_unused, nodiscard]] file_writer_config(file_writer_config const &rhs) noexcept(true == std::is_nothrow_copy_constructible_v<std::filesystem::path>) = default;
   [[nodiscard]] file_writer_config(std::filesystem::path &&filePath, file_writer_option const option) noexcept(true == std::is_nothrow_move_constructible_v<std::filesystem::path>);
   [[nodiscard]] file_writer_config(std::filesystem::path const &filePath, file_writer_option const option) noexcept(true == std::is_nothrow_copy_constructible_v<std::filesystem::path>);

   [[maybe_unused]] file_writer_config &operator = (file_writer_config &&rhs) noexcept(true == std::is_nothrow_move_assignable_v<std::filesystem::path>) = default;
   [[maybe_unused]] file_writer_config &operator = (file_writer_config const &rhs) noexcept(true == std::is_nothrow_copy_assignable_v<std::filesystem::path>) = default;

   [[maybe_unused, nodiscard]] std::filesystem::path const &path() const noexcept
   {
      return m_path;
   }

   [[maybe_unused, nodiscard]] file_writer_option option() const noexcept
   {
      return m_option;
   }

private:
   std::filesystem::path m_path;
   file_writer_option m_option;
};

}
