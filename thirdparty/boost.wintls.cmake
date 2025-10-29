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

if(IO_THREADS_SSL_LIBRARY STREQUAL "schannel")
   include(CMakeThirdpartyTargets)
   include(FetchContent)

   FetchContent_Declare(
      wintls
      # Download Step Options
      GIT_PROGRESS ON
      GIT_REMOTE_UPDATE_STRATEGY CHECKOUT
      GIT_REPOSITORY https://github.com/laudrup/boost-wintls.git
      GIT_SHALLOW ON
      GIT_SUBMODULES_RECURSE ON
      GIT_TAG v1.0.0
   )
   FetchContent_Populate(wintls)
   file(GLOB BOOST_WINTLS_HEADERS "${wintls_SOURCE_DIR}/include/*.hpp")
   add_library(boost_wintls INTERFACE ${BOOST_WINTLS_HEADERS})
   add_library(Boost::wintls ALIAS boost_wintls)
   target_include_directories(boost_wintls SYSTEM INTERFACE "${wintls_SOURCE_DIR}/include/")
   organize_thirdparty_target(boost_wintls thirdparty)
endif()
