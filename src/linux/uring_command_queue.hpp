/*
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
*/

#pragma once

#include "common/shared_memory_pool.hpp" ///< for io_threads::shared_memory_pool
#include "linux/uring_listener.hpp" ///< for io_threads::uring_listener

#include <cstddef> ///< for size_t
#include <cstdint> ///< for intptr_t
#include <memory> ///< for std::addressof
#include <mutex> ///< for std::mutex, std::scoped_lock
#include <new> ///< for std::align_val_t, std::launder

namespace io_threads
{

class uring_command_queue final
{
private:
   struct uring_command final
   {
      uring_command *next;
      intptr_t const id;
      intptr_t const target;
   };

public:
   uring_command_queue() = delete;
   uring_command_queue(uring_command_queue &&) = delete;
   uring_command_queue(uring_command_queue const &) = delete;

   [[nodiscard]] explicit uring_command_queue(size_t const commandQueueCapacity) :
      m_uringCommandsMemoryPool{commandQueueCapacity, std::align_val_t{alignof(uring_command)}, sizeof(uring_command)}
   {}

   uring_command_queue &operator = (uring_command_queue &&) = delete;
   uring_command_queue &operator = (uring_command_queue const &) = delete;

   void handle(uring_listener &uringListener)
   {
      uring_command *orderedUringCommands{nullptr,};
      auto *unorderedUringCommands{pop_uring_commands(),};
      while (nullptr != unorderedUringCommands)
      {
         auto *uringCommand{std::launder(unorderedUringCommands),};
         unorderedUringCommands = std::launder(uringCommand->next);
         uringCommand->next = std::launder(orderedUringCommands);
         orderedUringCommands = std::launder(uringCommand);
      }
      while (nullptr != orderedUringCommands)
      {
         auto *uringCommand{std::launder(orderedUringCommands),};
         orderedUringCommands = std::launder(uringCommand->next);
         uringCommand->next = nullptr;
         uringListener.handle_command(uringCommand->id, uringCommand->target);
         m_uringCommandsMemoryPool.push(*uringCommand);
      }
   }

   void push(intptr_t const commandId, intptr_t const commandTarget)
   {
      auto &uringCommand
      {
         m_uringCommandsMemoryPool.pop<uring_command>(
            uring_command{.next = nullptr, .id = commandId, .target = commandTarget,}
         ),
      };
      [[maybe_unused]] std::scoped_lock const uringCommandsGuard{m_uringCommandsLock,};
      uringCommand.next = std::launder(m_uringCommands);
      m_uringCommands = std::launder(std::addressof(uringCommand));
   }

private:
   shared_memory_pool m_uringCommandsMemoryPool;
   std::mutex m_uringCommandsLock{};
   uring_command *m_uringCommands{nullptr,};

   [[nodiscard]] uring_command *pop_uring_commands()
   {
      [[maybe_unused]] std::scoped_lock const uringCommandsGuard{m_uringCommandsLock,};
      auto *uringCommands{std::launder(m_uringCommands),};
      m_uringCommands = nullptr;
      return uringCommands;
   }
};

}
