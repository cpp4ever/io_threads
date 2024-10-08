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

get_filename_component(IO_THREADS_PROJECT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR} REALPATH)
get_filename_component(MAIN_PROJECT_SOURCE_DIR ${CMAKE_SOURCE_DIR} REALPATH)
if(IO_THREADS_PROJECT_SOURCE_DIR STREQUAL MAIN_PROJECT_SOURCE_DIR)
   set(IO_THREADS_DEV TRUE)
endif()

project(io_threads LANGUAGES CXX)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

add_subdirectory(thirdparty EXCLUDE_FROM_ALL)

find_package(OpenSSL QUIET)
find_package(Threads)

include(CMakeTargetCompiler)

file(GLOB_RECURSE IO_THREADS_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/include/*")
file(GLOB_RECURSE IO_THREADS_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/*")
add_library(io_threads STATIC ${IO_THREADS_HEADERS} ${IO_THREADS_SOURCES})
add_library(io_threads::io_threads ALIAS io_threads)
if(CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
   # Enable Language Extensions (windows headers does not compile without)
   set_target_properties(io_threads PROPERTIES CXX_EXTENSIONS ON)
endif()
set_target_default_cxx_compile_flags(io_threads PRIVATE)
source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}/include/io_threads/" PREFIX "include" FILES ${IO_THREADS_HEADERS})
source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}/src/" PREFIX "src" FILES ${IO_THREADS_SOURCES})
if(WIN32)
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

         WIN32_LEAN_AND_MEAN
   )
   # Minimal Windows wersions with TLS 1.3 support:
   #  - Windows 11, Version 21H2 (10.0.22000)
   #  - Windows Server 2022, Version 21H2 (10.0.20348)
   if(CMAKE_SYSTEM_VERSION VERSION_GREATER_EQUAL 10.0.20348)
      target_compile_definitions(io_threads PUBLIC IO_THREADS_TLSv1_3=1)
   endif()
elseif(OPENSSL_FOUND)
   if(OPENSSL_VERSION VERSION_GREATER_EQUAL 1.1.1)
      target_compile_definitions(io_threads PUBLIC IO_THREADS_TLSv1_3=1)
   endif()
endif()
target_include_directories(io_threads PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include/")
if(OPENSSL_FOUND)
   target_include_directories(io_threads PRIVATE "${OPENSSL_INCLUDE_DIR}")
   target_link_libraries(io_threads PRIVATE ${OPENSSL_LIBRARIES})
endif()
if(Threads_FOUND)
   target_link_libraries(io_threads PRIVATE Threads::Threads)
endif()

if(IO_THREADS_DEV)
   if(CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
      target_compile_options(io_threads PUBLIC /W4)
   else()
      target_compile_options(io_threads PUBLIC -Wall -Werror -Wextra -Wpedantic)
   endif()
   add_coverage(io_threads)

   enable_testing()
   add_subdirectory(tests)
   set_property(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}" PROPERTY VS_STARTUP_PROJECT io_threads_tests)

   coverage_evaluate()
endif()
