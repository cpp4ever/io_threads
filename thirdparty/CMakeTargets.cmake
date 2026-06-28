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

include(FetchContent)

FetchContent_Declare(
   CMakeTargets
   EXCLUDE_FROM_ALL
   SYSTEM
   # Download Step Options
   URL https://github.com/cpp4ever/CMakeTargets/archive/refs/tags/v2026.06.19.tar.gz
   URL_HASH SHA256=3537e9291f2633650f99384e3a004797b3abf01c488970e8b8329572a4175bff
   DOWNLOAD_EXTRACT_TIMESTAMP ON
)
FetchContent_MakeAvailable(CMakeTargets)
