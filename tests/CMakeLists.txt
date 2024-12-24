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

include(CMakeTargetCompiler)

file(GLOB_RECURSE IO_THREADS_TESTS_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/*.hpp")
file(GLOB_RECURSE IO_THREADS_TESTS_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")
add_executable(io_threads_tests ${IO_THREADS_TESTS_HEADERS} ${IO_THREADS_TESTS_SOURCES})
add_executable(io_threads::tests ALIAS io_threads_tests)
if(CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
   # Enable Language Extensions (windows headers does not compile without)
   set_target_properties(io_threads_tests PROPERTIES CXX_EXTENSIONS ON)
   target_compile_options(io_threads_tests PRIVATE /bigobj)
endif()
set_target_default_cxx_compile_flags(io_threads_tests PRIVATE)
set_target_properties(io_threads_tests PROPERTIES POSITION_INDEPENDENT_CODE TRUE)
setup_tls_and_crypto_library(io_threads_tests)
source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}/" FILES ${IO_THREADS_TESTS_HEADERS} ${IO_THREADS_TESTS_SOURCES})
target_include_directories(io_threads_tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(io_threads_tests PRIVATE Boost::beast gmock_main io_threads::io_threads)
if(IO_THREADS_TLS_AND_CRYPTO_LIBRARY STREQUAL "openssl")
   target_compile_definitions(io_threads_tests PRIVATE IO_THREADS_CBC_ALLOWED=1 IO_THREADS_DH2048_ALLOWED=1)
   if(OPENSSL_VERSION VERSION_GREATER_EQUAL "1.1.1")
      target_compile_definitions(io_threads_tests PRIVATE IO_THREADS_TLSv1_3_AVAILABLE=1)
   endif()
elseif(IO_THREADS_TLS_AND_CRYPTO_LIBRARY STREQUAL "schannel")
   target_compile_definitions(io_threads_tests PRIVATE IO_THREADS_CBC_ALLOWED=1)
   target_link_libraries(io_threads_tests PRIVATE Boost::wintls)
   # Minimal Windows wersions with TLS 1.3 support:
   #  - Windows 11, Version 21H2 (10.0.22000)
   #  - Windows Server 2022, Version 21H2 (10.0.20348)
   if(CMAKE_SYSTEM_VERSION VERSION_GREATER_EQUAL "10.0.20348")
      target_compile_definitions(io_threads_tests PRIVATE IO_THREADS_TLSv1_3_AVAILABLE=1)
   else()
      # 3DES, DH-1024 and DH-2048 are deprecated in newer versions of Windows,
      # but for older versions the corresponding tests should be skipped
      target_compile_definitions(
         io_threads_tests
         PRIVATE
            IO_THREADS_3DES_ALLOWED=1
            IO_THREADS_DH1024_ALLOWED=1
            IO_THREADS_DH2048_ALLOWED=1
      )
   endif()
endif()
if(NOT IO_THREADS_ENABLE_COVERAGE)
   available_cxx_sanitizers(CXX_SANITIZERS)
   list(LENGTH CXX_SANITIZERS CXX_SANITIZERS_LENGTH)
   if(CXX_SANITIZERS_LENGTH GREATER 0)
      list(GET CXX_SANITIZERS 0 DEFAULT_CXX_SANITIZER)
      set(IO_THREADS_SANITIZER ${DEFAULT_CXX_SANITIZER} CACHE STRING "Choose sanitizer for the build")
      set_property(CACHE IO_THREADS_SANITIZER PROPERTY STRINGS ${CXX_SANITIZERS})
      if(IO_THREADS_SANITIZER STREQUAL "UBSan")
         target_cxx_ubsan(
            io_threads_tests
            FLAGS
               exitcode=1
               print_stacktrace=true
               report_error_type=true
               silence_unsigned_overflow=true
         )
      else()
         target_cxx_sanitizer(io_threads_tests ${IO_THREADS_SANITIZER} FLAGS exitcode=1)
      endif()
   endif()
   get_filename_component(CXX_LINKER_DIRECTORY ${CMAKE_LINKER} DIRECTORY)
   string(LENGTH "${CXX_LINKER_DIRECTORY}" CXX_LINKER_DIRECTORY_LENGTH)
   if(CXX_LINKER_DIRECTORY_LENGTH GREATER 0)
      set(IO_THREADS_CTEST_PROPERTIES ENVIRONMENT "PATH=${CXX_LINKER_DIRECTORY}")
   endif()
endif()

include(GoogleTest)
gtest_discover_tests(io_threads_tests PROPERTIES ${IO_THREADS_CTEST_PROPERTIES})
