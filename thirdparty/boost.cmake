#[[
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
]]

include(CMakeThirdpartyTargets)
include(FetchContent)

FetchContent_Declare(
   boost
   # Download Step Options
   URL https://github.com/boostorg/boost/releases/download/boost-1.87.0/boost-1.87.0-cmake.tar.xz
   URL_HASH SHA256=7da75f171837577a52bbf217e17f8ea576c7c246e4594d617bfde7fafd408be5
   DOWNLOAD_EXTRACT_TIMESTAMP ON
)
FetchContent_MakeAvailable(boost)
if(CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
   # Enable Language Extensions
   set_target_properties(boost_container PROPERTIES CXX_EXTENSIONS ON)
   set_target_properties(boost_context PROPERTIES CXX_EXTENSIONS ON)
   set_target_properties(boost_coroutine PROPERTIES CXX_EXTENSIONS ON)
endif()
target_compile_definitions(
   boost_asio
   INTERFACE
      BOOST_ASIO_SEPARATE_COMPILATION=1
      $<$<PLATFORM_ID:Linux>:BOOST_ASIO_HAS_IO_URING=1>
      $<$<CXX_COMPILER_ID:GNU>:BOOST_ASIO_DISABLE_FENCED_BLOCK=1>
)
target_compile_definitions(boost_beast INTERFACE BOOST_BEAST_SEPARATE_COMPILATION=1)
organize_thirdparty_directory_targets("${boost_SOURCE_DIR}" thirdparty)
