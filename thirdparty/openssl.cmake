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

if(NOT OPENSSL_FOUND)
   set(OPENSSL_USE_STATIC_LIBS ON)
   find_package(OpenSSL REQUIRED)
   if(OPENSSL_FOUND)
      add_library(io_threads_openssl INTERFACE)
      add_library(io_threads::openssl ALIAS io_threads_openssl)
      target_include_directories(io_threads_openssl SYSTEM INTERFACE "${OPENSSL_INCLUDE_DIR}")
      target_link_libraries(io_threads_openssl INTERFACE ${OPENSSL_LIBRARIES})
      if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
         target_link_libraries(io_threads_openssl INTERFACE zlibstatic zstd)
      elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
         target_link_libraries(io_threads_openssl INTERFACE Crypt32)
      endif()
   endif()
endif()

function(setup_ssl_library IN_TARGET)
   target_compile_definitions(${IN_TARGET} PRIVATE IO_THREADS_OPENSSL=1 OPENSSL_NO_DEPRECATED=1)
   target_link_libraries(${IN_TARGET} PRIVATE io_threads::openssl)
endfunction()
