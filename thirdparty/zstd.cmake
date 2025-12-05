#[[
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
]]

if(NOT TARGET libzstd_static)
   include(CMakeThirdpartyTargets)
   include(FetchContent)

   set(ZSTD_BUILD_CONTRIB OFF CACHE BOOL "Disable contrib utilities" FORCE)
   set(ZSTD_BUILD_PROGRAMS OFF CACHE BOOL "Disable command-line programs" FORCE)
   set(ZSTD_BUILD_TESTS OFF CACHE BOOL "Disable test targets" FORCE)
   FetchContent_Declare(
      zstd
      # Download Step Options
      URL https://github.com/facebook/zstd/releases/download/v1.5.7/zstd-1.5.7.tar.zst
      URL_HASH SHA256=5b331d961d6989dc21bb03397fc7a2a4d86bc65a14adc5ffbbce050354e30fd2
      DOWNLOAD_EXTRACT_TIMESTAMP ON
      SOURCE_SUBDIR build/cmake
   )
   FetchContent_MakeAvailable(zstd)
   if(CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
      # Enable Language Extensions
      set_target_properties(libzstd_static PROPERTIES C_EXTENSIONS ON)
   endif()
   organize_thirdparty_target(libzstd_static thirdparty)
endif()
