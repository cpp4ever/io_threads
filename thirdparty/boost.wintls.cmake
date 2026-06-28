#[[
   Part of the io_threads project (https://github.com/cpp4ever/io_threads), under the MIT License
   SPDX-License-Identifier: MIT

   Copyright (c) 2024-2026 Mikhail Smirnov

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

if(IO_THREADS_SSL_LIBRARY STREQUAL "schannel")
   include(CMakeThirdpartyTargets)
   include(ExternalProject)

   ExternalProject_Add(
      wintls
      # Download Step Options
      URL https://github.com/laudrup/boost-wintls/archive/refs/tags/v1.0.0.tar.gz
      URL_HASH SHA256=e5aa70d508ad709f25d6d6a1802e956b5706fe2d2761b619303ef6a851267e69
      DOWNLOAD_EXTRACT_TIMESTAMP ON
      # Configure Step Options
      CONFIGURE_COMMAND ""
      CONFIGURE_HANDLED_BY_BUILD ON
      # Build Step Options
      BUILD_COMMAND ""
      # Install Step Options
      INSTALL_COMMAND ""
      # Test Step Options
      TEST_COMMAND ""
      # Target Options
      EXCLUDE_FROM_ALL ON
   )
   ExternalProject_Get_Property(wintls SOURCE_DIR)
   file(GLOB BOOST_WINTLS_HEADERS "${SOURCE_DIR}/include/*.hpp")
   add_library(boost_wintls INTERFACE ${BOOST_WINTLS_HEADERS})
   add_library(Boost::wintls ALIAS boost_wintls)
   add_dependencies(boost_wintls wintls)
   target_include_directories(boost_wintls SYSTEM INTERFACE "${SOURCE_DIR}/include/")
   organize_thirdparty_target(boost_wintls thirdparty)
endif()
