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
   URL https://github.com/boostorg/boost/releases/download/boost-1.86.0/boost-1.86.0-cmake.tar.xz
   URL_HASH SHA3_256=bc535064f8d7dd9310c61497e0d461553e1dfba6fb2fbe29f0b25e6b9452e97f
   DOWNLOAD_EXTRACT_TIMESTAMP ON
)
FetchContent_MakeAvailable(boost)
if(CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
   # Enable Language Extensions
   set_target_properties(boost_container PROPERTIES CXX_EXTENSIONS ON)
   set_target_properties(boost_context PROPERTIES CXX_EXTENSIONS ON)
   set_target_properties(boost_coroutine PROPERTIES CXX_EXTENSIONS ON)
endif()
organize_thirdparty_directory_targets("${boost_SOURCE_DIR}" thirdparty)
