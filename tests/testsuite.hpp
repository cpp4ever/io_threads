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

#include <gtest/gtest.h>

#include <random>
#include <string>
#include <type_traits>

namespace io_threads::tests
{

class testsuite : public testing::Test
{
private:
   using super = testing::Test;

public:
   testsuite() = default;
   testsuite(testsuite &&) = delete;
   testsuite(testsuite const &) = delete;

   testsuite &operator = (testsuite &&) = delete;
   testsuite &operator = (testsuite const &) = delete;

   [[nodiscard]] bool random_bool()
   {
      return 1 == random_number(0, 1);
   }

   template<typename type>
   [[nodiscard]] type random_number(type const lowerBound, type const upperBound)
      requires(true == std::is_floating_point_v<type>)
   {
      return std::uniform_real_distribution<type>{lowerBound, upperBound}(m_randomEngine);
   }

   template<typename type>
   [[nodiscard]] type random_number(type const lowerBound, type const upperBound)
      requires((true == std::is_integral_v<type>) && (sizeof(type) < sizeof(int)))
   {
      static_assert(false == std::is_same_v<bool, type>, "Please call random_bool instead");
      return static_cast<type>(std::uniform_int_distribution<int>{lowerBound, upperBound}(m_randomEngine));
   }

   template<typename type>
   [[nodiscard]] type random_number(type const lowerBound, type const upperBound)
      requires((true == std::is_integral_v<type>) && (sizeof(type) >= sizeof(int)))
   {
      return std::uniform_int_distribution<type>{lowerBound, upperBound}(m_randomEngine);
   }

   [[nodiscard]] std::string random_string(size_t length);

   [[nodiscard]] std::string random_string(size_t const minLength, size_t const maxLength)
   {
      return random_string(random_number(minLength, maxLength));
   }

protected:
   void SetUp() override;

private:
   std::mt19937_64 m_randomEngine{};
};

}
