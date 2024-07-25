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

cmake_minimum_required(VERSION 3.20)

project(io_threads LANGUAGES CXX)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

get_filename_component(IO_THREADS_PROJECT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR} REALPATH)
get_filename_component(MAIN_PROJECT_SOURCE_DIR ${CMAKE_SOURCE_DIR} REALPATH)
if(IO_THREADS_PROJECT_SOURCE_DIR STREQUAL MAIN_PROJECT_SOURCE_DIR)
   set(IO_THREADS_DEV TRUE)
   if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
      set(IO_THREADS_ENABLE_COVERAGE OFF CACHE BOOL "Enable code coverage")
      if(IO_THREADS_ENABLE_COVERAGE)
         add_compile_options(-fprofile-arcs -ftest-coverage)
         add_link_options(-fprofile-arcs -ftest-coverage)
      endif()
   endif()
endif()
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
   set(IO_THREADS_NATIVE_SSL_LIBRARY "openssl")
   set(IO_THREADS_SSL_LIBRARIES "openssl")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
   set(IO_THREADS_NATIVE_SSL_LIBRARY "schannel")
   set(IO_THREADS_SSL_LIBRARIES "schannel;openssl")
else()
   message(FATAL_ERROR "${CMAKE_SYSTEM_NAME} not supported")
endif()
set(IO_THREADS_SSL_LIBRARY "${IO_THREADS_NATIVE_SSL_LIBRARY}" CACHE STRING "Choose SSL library for the build")
set_property(CACHE IO_THREADS_SSL_LIBRARY PROPERTY STRINGS "${IO_THREADS_SSL_LIBRARIES}")

find_package(Threads)

add_subdirectory(thirdparty EXCLUDE_FROM_ALL)

include(CMakeTargetCompiler)

file(GLOB_RECURSE IO_THREADS_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/include/*")
file(GLOB_RECURSE IO_THREADS_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/*")
add_library(io_threads STATIC ${IO_THREADS_HEADERS} ${IO_THREADS_SOURCES})
add_library(io_threads::io_threads ALIAS io_threads)
if(CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
   # Enable Language Extensions (for WinAPI headers)
   set_target_properties(io_threads PROPERTIES CXX_EXTENSIONS ON)
endif()
set_target_default_cxx_compile_flags(io_threads PRIVATE)
setup_ssl_library(io_threads)
source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}/include/io_threads/" PREFIX "include" FILES ${IO_THREADS_HEADERS})
source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}/src/" PREFIX "src" FILES ${IO_THREADS_SOURCES})
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
   target_link_libraries(io_threads PRIVATE uring)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
   target_compile_definitions(
      io_threads
      PRIVATE
         NOATOM            # Atom Manager routines
         NOCLIPBOARD       # Clipboard routines
         NOCOLOR           # Screen colors
         NOCOMM            # COMM driver routines
         NOCTLMGR          # Control and Dialog routines
         NODEFERWINDOWPOS  # DeferWindowPos routines
         NODRAWTEXT        # DrawText() and DT_*
         NOGDI             # All GDI defines and routines
         NOGDICAPMASKS     # CC_*, LC_*, PC_*, CP_*, TC_*, RC_
         NOHELP            # Help engine interface
         NOICONS           # IDI_*
         NOIME             # Input Method Manager definitions
         NOKANJI           # Kanji support stuff
         NOKERNEL          # All KERNEL defines and routines
         NOKEYSTATES       # MK_*
         NOMB              # MB_* and MessageBox()
         NOMCX             # Modem Configuration Extensions
         NOMEMMGR          # GMEM_*, LMEM_*, GHND, LHND, associated routines
         NOMENUS           # MF_*
         NOMETAFILE        # typedef METAFILEPICT
         NOMINMAX          # Macros min(a,b) and max(a,b)
         NOMSG             # typedef MSG and associated routines
         NOOPENFILE        # OpenFile(), OemToAnsi, AnsiToOem, and OF_*
         NOPROFILER        # Profiler interface
         NORASTEROPS       # Binary and Tertiary raster ops
         NOSCROLL          # SB_* and scrolling routines
         NOSERVICE         # All Service Controller routines, SERVICE_ equates, etc
         NOSHOWWINDOW      # SW_*
         NOSOUND           # Sound driver routines
         NOSYSCOMMANDS     # SC_*
         NOSYSMETRICS      # SM_*
         NOTEXTMETRIC      # typedef TEXTMETRIC and associated routines
         NOUSER            # All USER defines and routines
         NOVIRTUALKEYCODES # VK_*
         NOWH              # SetWindowsHook and WH_*
         NOWINMESSAGES     # WM_*, EM_*, LB_*, CB_*
         NOWINOFFSETS      # GWL_*, GCL_*, associated routines
         NOWINRES          # Windows resource codes
         NOWINSTYLES       # WS_*, CS_*, ES_*, LBS_*, SBS_*, CBS_*

         SCHANNEL_USE_BLACKLISTS
         SECURITY_WIN32

         WIN32_LEAN_AND_MEAN
   )
endif()
target_include_directories(
   io_threads
   PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src/"
   PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include/"
)
target_link_libraries(io_threads PRIVATE zlibstatic PUBLIC llhttp_static)
if(Threads_FOUND)
   target_link_libraries(io_threads PRIVATE Threads::Threads)
endif()

if(IO_THREADS_DEV)
   if(CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
      target_compile_options(io_threads PUBLIC /W4 /WX)
   else()
      target_compile_options(io_threads PUBLIC -Wall -Werror -Wextra -Wpedantic)
   endif()

   enable_testing()
   add_subdirectory(tests)
   set_property(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}" PROPERTY VS_STARTUP_PROJECT io_threads_tests)
endif()
