/*
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
*/

#include "common/wss_client_context_impl.hpp" ///< for io_threads::wss_client_context::wss_client_context_impl
#include "io_threads/tls_client_context.hpp" ///< for io_threads::tls_client_context
#include "io_threads/wss_client_context.hpp" ///< for io_threads::wss_client_context

#include <cassert> ///< for assert
#include <cstddef> ///< for size_t
#include <memory> ///< for std::make_unique

namespace io_threads
{

wss_client_context::wss_client_context(wss_client_context &&rhs) noexcept = default;
wss_client_context::wss_client_context(wss_client_context const &rhs) noexcept = default;

wss_client_context::wss_client_context(
   tls_client_context const &tlsClientContext,
   size_t const wssSessionListCapacity,
   size_t const wssBufferCatacity
) :
   m_tlsClientContext{tlsClientContext,}
{
   executor().execute(
      [this, wssSessionListCapacity, wssBufferCatacity] ()
      {
         m_impl = std::make_unique<wss_client_context_impl>(
            wssSessionListCapacity,
            wssBufferCatacity
         );
      }
   );
   assert(nullptr != m_impl);
}

wss_client_context::~wss_client_context()
{
   assert(nullptr != m_impl);
   executor().execute(
      [this] ()
      {
         m_impl.reset();
      }
   );
   assert(nullptr == m_impl);
}

wss_client_context &wss_client_context::operator = (wss_client_context &&rhs) noexcept = default;
wss_client_context &wss_client_context::operator = (wss_client_context const &rhs) = default;

}
