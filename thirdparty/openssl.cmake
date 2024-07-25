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

if(NOT OPENSSL_FOUND)
   set(OPENSSL_USE_STATIC_LIBS ON)
   find_package(OpenSSL)
   if(OPENSSL_FOUND)
      add_library(io_threads_openssl INTERFACE)
      add_library(io_threads::openssl ALIAS io_threads_openssl)
      target_include_directories(io_threads_openssl INTERFACE "${OPENSSL_INCLUDE_DIR}")
      target_link_libraries(io_threads_openssl INTERFACE ${OPENSSL_LIBRARIES})
      if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
         target_link_libraries(io_threads_openssl INTERFACE zstd)
      elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
         target_link_libraries(io_threads_openssl INTERFACE Crypt32)
      endif()
   endif()
endif()

function(setup_ssl_library IN_TARGET)
   target_compile_definitions(${IN_TARGET} PRIVATE IO_THREADS_OPENSSL=1 OPENSSL_NO_DEPRECATED=1)
   if(TARGET io_threads_openssl)
      target_link_libraries(${IN_TARGET} PRIVATE io_threads::openssl)
   else()
      set(OPENSSL_VERSION "3.0.16")
      configure_file("${CMAKE_CURRENT_FUNCTION_LIST_DIR}/openssl/packages.config" "${CMAKE_CURRENT_BINARY_DIR}/packages.${IN_TARGET}.config" @ONLY)
      configure_file("${CMAKE_CURRENT_FUNCTION_LIST_DIR}/openssl/user.props" "${CMAKE_CURRENT_BINARY_DIR}/${IN_TARGET}.user.props" @ONLY)
      set_target_properties(
         ${IN_TARGET}
         PROPERTIES
            VS_PACKAGE_REFERENCES "openssl-native_${OPENSSL_VERSION}"
            VS_USER_PROPS "${CMAKE_CURRENT_BINARY_DIR}/${IN_TARGET}.user.props"
      )
      target_link_libraries(${IN_TARGET} PRIVATE libcrypto libssl)
   endif()
endfunction()
