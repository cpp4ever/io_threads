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

if(NOT TARGET zlibstatic)
   include(CMakeThirdpartyTargets)
   include(FetchContent)

   set(SKIP_INSTALL_ALL OFF)
   set(ZLIB_BUILD_EXAMPLES OFF CACHE BOOL "Disable examples targets" FORCE)
   FetchContent_Declare(
      zlib
      # Download Step Options
      URL https://zlib.net/zlib-1.3.1.tar.xz
      URL_HASH SHA256=38ef96b8dfe510d42707d9c781877914792541133e1870841463bfa73f883e32
      DOWNLOAD_EXTRACT_TIMESTAMP ON
   )
   FetchContent_MakeAvailable(zlib)
   if(CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
      # Enable Language Extensions
      set_target_properties(zlibstatic PROPERTIES C_EXTENSIONS ON)
   endif()
   organize_thirdparty_target(zlibstatic thirdparty)
endif()
