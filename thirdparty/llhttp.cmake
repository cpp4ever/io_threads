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

if(NOT TARGET llhttp_static)
   include(CMakeThirdpartyTargets)
   include(FetchContent)

   set(BUILD_SHARED_LIBS OFF CACHE BOOL "Disable shared libraries targets" FORCE)
   set(BUILD_STATIC_LIBS ON CACHE BOOL "Enable static libraries targets" FORCE)
   FetchContent_Declare(
      llhttp
      # Download Step Options
      URL https://github.com/nodejs/llhttp/archive/refs/tags/release/v9.2.1.tar.gz
      URL_HASH SHA256=3c163891446e529604b590f9ad097b2e98b5ef7e4d3ddcf1cf98b62ca668f23e
      DOWNLOAD_EXTRACT_TIMESTAMP ON
   )
   FetchContent_MakeAvailable(llhttp)
   organize_thirdparty_target(llhttp_static thirdparty)
endif()
