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

#pragma once

#include "common/logger.hpp" ///< for io_threads::log_error
#include "common/object_pool.hpp" ///< for io_threads::object_pool
#include "common/utility.hpp" ///< for io_threads::to_underlying, io_threads::unreachable
#include "io_threads/network_interface.hpp" ///< for io_threads::network_interface
#include "io_threads/tcp_client.hpp" ///< for io_threads::tcp_client_thread::tcp_client
#include "io_threads/tcp_client_config.hpp" ///< for io_threads::tcp_client_config
#include "io_threads/tcp_client_thread.hpp" ///< for io_threads::tcp_client_thread::tcp_client_impl
#include "windows/completion_port.hpp" ///< for io_threads::completion_port
#include "windows/socket_address_impl.hpp" ///< for io_threads::socket_address::socket_address_impl
#include "windows/tcp_client_command.hpp" ///< for io_threads::tcp_client_command, io_threads::from_completion_overlapped
#include "windows/tcp_connectivity_context.hpp" ///< for io_threads::tcp_connectivity_context
#include "windows/tcp_data_transfer_context.hpp" ///< for io_threads::tcp_data_transfer_context
#include "windows/tcp_socket_descriptor.hpp" ///< for io_threads::tcp_socket_descriptor
#include "windows/winsock_error.hpp" ///< for io_threads::check_winsock_error, io_threads::check_winsock_error_if_not

/// for
///   AF_INET,
///   AF_INET6,
///   bind,
///   CopyMemory,
///   closesocket,
///   DWORD,
///   ERROR_SUCCESS,
///   FALSE,
///   INVALID_SOCKET,
///   IPPROTO_TCP,
///   LPSOCKADDR,
///   MoveMemory,
///   OVERLAPPED_ENTRY,
///   setsockopt,
///   SO_KEEPALIVE,
///   SOCK_STREAM,
///   SOCKADDR,
///   SOCKADDR_IN,
///   SOCKET,
///   SOCKET_ADDRESS,
///   SOCKET_ERROR,
///   SOL_SOCKET,
///   TCP_KEEPCNT,
///   TCP_KEEPIDLE,
///   TCP_KEEPINTVL,
///   TCP_MAXRT,
///   TCP_NODELAY,
///   TRUE,
///   ULONG_PTR,
///   WSA_FLAG_NO_HANDLE_INHERIT,
///   WSA_FLAG_OVERLAPPED,
///   WSA_IO_PENDING,
///   WSAEHOSTUNREACH,
///   WSAGetLastError,
///   WSAGetOverlappedResult,
///   WSASocketW
#include <WinSock2.h>
/// for
///   LPFN_CONNECTEX,
///   LPFN_DISCONNECTEX,
///   WSAID_CONNECTEX,
///   WSAID_DISCONNECTEX
#include <MSWSock.h>
#include <ws2ipdef.h> ///< for SOCKADDR_IN6
#include <WS2tcpip.h> ///< for ICMP_ERROR_INFO, WSAGetIcmpErrorInfo, WSASetFailConnectOnIcmpError

#include <algorithm> ///< for std::max
#include <bit> ///< for std::bit_cast
#include <cassert> ///< for assert
#include <chrono> ///< for std::chrono::milliseconds
#include <cstddef> ///< for size_t
#include <cstdlib> ///< for std::abort
#include <memory> ///< for std::addressof
#include <new> ///< for std::align_val_t, operator delete, operator new
#include <source_location> ///< for std::source_location
#include <system_error> ///< for std::error_code
#include <variant> ///< for std::visit

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "WS2_32.lib")

namespace io_threads
{

class tcp_client_thread::tcp_client::tcp_client_thread_worker final
{
public:
   tcp_client_thread_worker() = delete;
   tcp_client_thread_worker(tcp_client_thread_worker &&) = delete;
   tcp_client_thread_worker(tcp_client_thread_worker const &) = delete;

   [[nodiscard]] tcp_client_thread_worker(
      size_t const initialCapacityOfSocketDescriptors,
      size_t const recvBufferSize,
      size_t const sendBufferSize
   ) :
      m_sendContexts{initialCapacityOfSocketDescriptors, sizeof(tcp_data_transfer_context) + sendBufferSize},
      m_recvContexts{initialCapacityOfSocketDescriptors, sizeof(tcp_data_transfer_context) + recvBufferSize},
      m_socketDescriptors{initialCapacityOfSocketDescriptors},
      m_connectivityContexts
      {
         initialCapacityOfSocketDescriptors,
         sizeof(tcp_connectivity_context) + std::max(sizeof(SOCKADDR_IN), sizeof(SOCKADDR_IN6))
      }
   {
      assert(0 < recvBufferSize);
      constexpr int socketFamily = AF_INET;
      constexpr int socketType = SOCK_STREAM;
      constexpr int socketProtocol = IPPROTO_TCP;
      constexpr LPWSAPROTOCOL_INFOW protocolInfo = nullptr;
      constexpr GROUP socketGroup = 0;
      constexpr DWORD flags = 0;
      auto const socket = WSASocketW(socketFamily, socketType, socketProtocol, protocolInfo, socketGroup, flags);
      if (INVALID_SOCKET == socket) [[unlikely]]
      {
         check_winsock_error("[tcp_client] failed to create TCP socket: ({}) - {}");
         unreachable();
      }
      if (SOCKET_ERROR == get_extension_function_pointer(socket, WSAID_CONNECTEX, m_connect))
      {
         check_winsock_error("[tcp_client] failed to get ConnectEx extension function pointer: ({}) - {}");
         unreachable();
      }
      if (SOCKET_ERROR == get_extension_function_pointer(socket, WSAID_DISCONNECTEX, m_disconnect))
      {
         check_winsock_error("[tcp_client] failed to get DisconnectEx extension function pointer: ({}) - {}");
         unreachable();
      }
      if (SOCKET_ERROR == closesocket(socket))
      {
         check_winsock_error("[tcp_client] failed to close TCP socket: ({}) - {}");
      }
   }

   tcp_client_thread_worker &operator = (tcp_client_thread_worker &&) = delete;
   tcp_client_thread_worker &operator = (tcp_client_thread_worker const &) = delete;

   void ready_to_connect(tcp_client_thread::tcp_client &client)
   {
      if (std::this_thread::get_id() == m_threadId)
      {
         handle_ready_to_connect(client);
      }
      else
      {
         m_completionPort.post_queued_completion_status(
            to_completion_key(client),
            to_completion_overlapped(tcp_client_command::ready_to_connect)
         );
      }
   }

   void ready_to_disconnect(tcp_client_thread::tcp_client &client)
   {
      if (std::this_thread::get_id() == m_threadId)
      {
         handle_ready_to_disconnect(client);
      }
      else
      {
         m_completionPort.post_queued_completion_status(
            to_completion_key(client),
            to_completion_overlapped(tcp_client_command::ready_to_disconnect)
         );
      }
   }

   void ready_to_send(tcp_client_thread::tcp_client &client)
   {
      if (std::this_thread::get_id() == m_threadId)
      {
         handle_ready_to_send(client);
      }
      else
      {
         m_completionPort.post_queued_completion_status(
            to_completion_key(client),
            to_completion_overlapped(tcp_client_command::ready_to_send)
         );
      }
   }

   void start(std::stop_token const stopToken)
   {
      while (false == stopToken.stop_requested()) [[likely]]
      {
         auto timeoutMilliseconds = completion_port::infinite_timeout;
         while (m_completionPortEntries.size() == poll(timeoutMilliseconds))
         {
            /// Do while there are entries to poll
            timeoutMilliseconds = completion_port::no_timeout;
         }
      }
      while (0 != poll(completion_port::no_timeout))
      {
         /// Until all entries are polled
      }
   }

   void stop()
   {
      m_completionPort.post_queued_completion_status(0, to_completion_overlapped(tcp_client_command::unknown));
   }

private:
   std::thread::id const m_threadId = std::this_thread::get_id();
   completion_port m_completionPort = {};
   completion_port::entries m_completionPortEntries = {};
   object_pool<tcp_data_transfer_context> m_sendContexts;
   object_pool<tcp_data_transfer_context> m_recvContexts;
   object_pool<tcp_socket_descriptor> m_socketDescriptors;
   object_pool<tcp_connectivity_context> m_connectivityContexts;
   LPFN_CONNECTEX m_connect = nullptr;
   LPFN_DISCONNECTEX m_disconnect = nullptr;

   void connect(tcp_client &client)
   {
      assert(nullptr != client.m_socketDescriptor);
      auto &socketDescriptor = *client.m_socketDescriptor;
      assert(INVALID_SOCKET != socketDescriptor.handle);
      assert(nullptr == socketDescriptor.recvContext);
      assert(nullptr == socketDescriptor.sendContext);
      assert(nullptr != socketDescriptor.connectivityContext);
      assert(nullptr != socketDescriptor.connectivityContext->address);
      auto &address = *socketDescriptor.connectivityContext->address;
      assert((AF_INET == address.sa_family) || (AF_INET6 == address.sa_family));
      assert(nullptr != m_connect);
      int const addressSize = (AF_INET6 == address.sa_family)
         ? sizeof(SOCKADDR_IN6)
         : sizeof(SOCKADDR_IN)
      ;
      constexpr PVOID sendBuffer = nullptr;
      constexpr DWORD sendDataLength = 0;
      DWORD bytesSent = 0;
      if (
         FALSE == (*m_connect)(
            socketDescriptor.handle,
            std::addressof(address),
            addressSize,
            sendBuffer,
            sendDataLength,
            std::addressof(bytesSent),
            std::addressof(socketDescriptor.connectivityContext->overlapped)
         )
      ) [[likely]]
      {
         if (
            auto const errorCode = check_winsock_error_if_not("[tcp_client] failed to connect TCP socket: ({}) - {}", WSA_IO_PENDING);
            errorCode
         ) [[unlikely]]
         {
            handle_disconnected(client, errorCode);
         }
      }
   }

   void disconnect(tcp_client &client)
   {
      assert(nullptr != client.m_socketDescriptor);
      auto &socketDescriptor = *client.m_socketDescriptor;
      assert(INVALID_SOCKET != socketDescriptor.handle);
      assert(nullptr != socketDescriptor.recvContext);
      assert(nullptr == socketDescriptor.sendContext);
      assert(nullptr != socketDescriptor.connectivityContext);
      assert(nullptr == socketDescriptor.connectivityContext->address);
      assert(nullptr != m_disconnect);
      constexpr DWORD flags = 0;
      constexpr DWORD reserved = 0;
      if (
         FALSE == (*m_disconnect)(
            socketDescriptor.handle,
            std::addressof(socketDescriptor.connectivityContext->overlapped),
            flags,
            reserved
         )
      ) [[likely]]
      {
         if (
            auto const errorCode = check_winsock_error_if_not("[tcp_client] failed to disconnect TCP socket: ({}) - {}", WSA_IO_PENDING);
            errorCode
         ) [[unlikely]]
         {
            handle_disconnected(client, errorCode);
         }
      }
   }

   void handle_completion_port_entry(OVERLAPPED_ENTRY const &completionPortEntry)
   {
      auto *client = from_completion_key<tcp_client>(completionPortEntry.lpCompletionKey);
      switch (from_completion_overlapped(completionPortEntry.lpOverlapped))
      {
      case tcp_client_command::unknown:
      {
         /// Generated by dtor of io_threads::tcp_client_thread::tcp_client_thread_impl
         assert(nullptr == client);
      }
      break;

      case tcp_client_command::ready_to_connect:
      {
         assert(nullptr != client);
         handle_ready_to_connect(*client);
      }
      break;

      case tcp_client_command::ready_to_disconnect:
      {
         assert(nullptr != client);
         handle_ready_to_disconnect(*client);
      }
      break;

      case tcp_client_command::ready_to_send:
      {
         assert(nullptr != client);
         handle_ready_to_send(*client);
      }
      break;

      default:
      {
         /// Generated by ConnectEx, DisconnectEx, WSARecv or WSASend
         assert(nullptr != client);
         if (nullptr == client->m_socketDescriptor) [[unlikely]]
         {
            return;
         }
         if (
            (nullptr != client->m_socketDescriptor->recvContext) &&
            (std::addressof(client->m_socketDescriptor->recvContext->overlapped) == completionPortEntry.lpOverlapped)
         )
         {
            handle_recv_completion(*client);
         }
         else if (
            (nullptr != client->m_socketDescriptor->sendContext) &&
            (std::addressof(client->m_socketDescriptor->sendContext->overlapped) == completionPortEntry.lpOverlapped)
         )
         {
            handle_send_completion(*client);
         }
         else if (
            (nullptr != client->m_socketDescriptor->connectivityContext) &&
            (std::addressof(client->m_socketDescriptor->connectivityContext->overlapped) == completionPortEntry.lpOverlapped)
         )
         {
            if (nullptr != client->m_socketDescriptor->connectivityContext->address)
            {
               handle_connect_completion(*client);
            }
            else
            {
               handle_disconnect_completion(*client);
            }
         }
         else [[unlikely]]
         {
            log_error(
               std::source_location::current(),
               "[tcp_client] unexpected completion overlapped: it must be a bug"
            );
            unreachable();
         }
      }
      break;
      }
   }

   void handle_connect_completion(tcp_client &client)
   {
      assert(nullptr != client.m_socketDescriptor);
      auto &socketDescriptor = *client.m_socketDescriptor;
      assert(INVALID_SOCKET != socketDescriptor.handle);
      assert(nullptr == socketDescriptor.recvContext);
      assert(nullptr == socketDescriptor.sendContext);
      assert(nullptr != socketDescriptor.connectivityContext);
      assert(nullptr != socketDescriptor.connectivityContext->address);
      DWORD bytesTransferred = 0;
      DWORD flags = 0;
      if (
         TRUE == WSAGetOverlappedResult(
            socketDescriptor.handle,
            std::addressof(socketDescriptor.connectivityContext->overlapped),
            std::addressof(bytesTransferred),
            FALSE,
            std::addressof(flags)
         )
      ) [[likely]]
      {
         if (SOCKET_ERROR == setsockopt(socketDescriptor.handle, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, nullptr, 0)) [[unlikely]]
         {
            check_winsock_error("[tcp_client] failed to set SO_UPDATE_CONNECT_CONTEXT socket option: ({}) - {}");
         }
         m_connectivityContexts.push(*socketDescriptor.connectivityContext);
         socketDescriptor.connectivityContext = nullptr;
         client.io_connected();
         socketDescriptor.recvContext = std::addressof(make_data_transfer_context(m_recvContexts));
         recv(client);
         send(client);
      }
      else
      {
         /// It must be a connectivity issue or shutdown on the peer side
         auto const errorCode = check_winsock_error("[tcp_client] failed to connect TCP socket: ({}) - {}");
#if (defined(TCP_ICMP_ERROR_INFO))
         if (std::error_code{WSAEHOSTUNREACH, std::generic_category()} == errorCode)
         {
            ICMP_ERROR_INFO icmpErrorInfo = {};
            if (SOCKET_ERROR != WSAGetIcmpErrorInfo(socketDescriptor.handle, std::addressof(icmpErrorInfo)))
            {
               socket_address::socket_address_impl socketAddress{icmpErrorInfo.srcaddress};
               log_error(
                  std::source_location::current(),
                  "[tcp_client] ICMP error info: srcaddress={} protocol={} type={} code={}",
                  std::string_view{socketAddress},
                  to_underlying(icmpErrorInfo.protocol),
                  icmpErrorInfo.type,
                  icmpErrorInfo.code
               );
            }
         }
#endif
         handle_disconnected(client, errorCode);
      }
   }

   void handle_disconnect_completion(tcp_client &client)
   {
      assert(nullptr != client.m_socketDescriptor);
      auto &socketDescriptor = *client.m_socketDescriptor;
      assert(INVALID_SOCKET != socketDescriptor.handle);
      assert(nullptr == socketDescriptor.sendContext);
      assert(nullptr != socketDescriptor.connectivityContext);
      assert(nullptr == socketDescriptor.connectivityContext->address);
      DWORD bytesTransferred = 0;
      DWORD flags = 0;
      if (
         FALSE == WSAGetOverlappedResult(
            socketDescriptor.handle,
            std::addressof(socketDescriptor.connectivityContext->overlapped),
            std::addressof(bytesTransferred),
            FALSE,
            std::addressof(flags)
         )
      ) [[unlikely]]
      {
         /// It must be a connectivity issue or shutdown on the peer side
         check_winsock_error("[tcp_client] failed to disconnect TCP socket: ({}) - {}");
      }
      handle_disconnected(client, std::error_code{});
   }

   void handle_disconnected(tcp_client &client, std::error_code errorCode)
   {
      assert(nullptr != client.m_socketDescriptor);
      auto &socketDescriptor = *client.m_socketDescriptor;
      assert(INVALID_SOCKET != socketDescriptor.handle);
      if (SOCKET_ERROR == closesocket(socketDescriptor.handle)) [[unlikely]]
      {
         check_winsock_error("[tcp_client] failed to close TCP socket: ({}) - {}");
      }
      socketDescriptor.handle = INVALID_SOCKET;
      if (nullptr != socketDescriptor.recvContext)
      {
         m_recvContexts.push(*socketDescriptor.recvContext);
         socketDescriptor.recvContext = nullptr;
      }
      if (nullptr != socketDescriptor.sendContext)
      {
         m_sendContexts.push(*socketDescriptor.sendContext);
         socketDescriptor.sendContext = nullptr;
      }
      if (nullptr != socketDescriptor.connectivityContext)
      {
         m_connectivityContexts.push(*socketDescriptor.connectivityContext);
         socketDescriptor.connectivityContext = nullptr;
      }
      if (socketDescriptor.disconnectReason)
      {
         errorCode = socketDescriptor.disconnectReason;
      }
      m_socketDescriptors.push(socketDescriptor);
      client.m_socketDescriptor = nullptr;
      client.io_disconnected(errorCode);
   }

   void handle_ready_to_connect(tcp_client &client)
   {
      assert(nullptr == client.m_socketDescriptor);
      auto const config = client.io_ready_to_connect();
      auto const &socketAddress = config.peer_address().socket_address()->sockaddr();
      auto const socket = WSASocketW(
         socketAddress.si_family,
         SOCK_STREAM,
         IPPROTO_TCP,
         nullptr,
         0,
         WSA_FLAG_NO_HANDLE_INHERIT | WSA_FLAG_OVERLAPPED
      );
      if (INVALID_SOCKET != socket) [[likely]]
      {
         m_completionPort.add_handle(std::bit_cast<HANDLE>(socket), to_completion_key(client));
         if (
            auto const errorCode = apply_socket_config(socket, config);
            errorCode
         ) [[unlikely]]
         {
            if (SOCKET_ERROR == closesocket(socket)) [[unlikely]]
            {
               check_winsock_error("[tcp_client] failed to close TCP socket: ({}) - {}");
            }
            client.io_disconnected(errorCode);
         }
         else
         {
            auto &connectivityContext = make_connect_context(m_connectivityContexts);
            assert(nullptr != connectivityContext.address);
            CopyMemory(
               connectivityContext.address,
               std::addressof(socketAddress),
               std::max(sizeof(SOCKADDR_IN), sizeof(SOCKADDR_IN6))
            );
            auto &socketDescriptor = m_socketDescriptors.pop();
            assert(INVALID_SOCKET == socketDescriptor.handle);
            assert(nullptr == socketDescriptor.recvContext);
            assert(nullptr == socketDescriptor.sendContext);
            assert(nullptr == socketDescriptor.connectivityContext);
            socketDescriptor.handle = socket;
            socketDescriptor.connectivityContext = std::addressof(connectivityContext);
            client.m_socketDescriptor = std::addressof(socketDescriptor);
            connect(client);
         }
      }
      else
      {
         client.io_disconnected(check_winsock_error("[tcp_client] failed to create TCP socket: ({}) - {}"));
      }
   }

   void handle_ready_to_disconnect(tcp_client &client)
   {
      assert(nullptr != client.m_socketDescriptor);
      auto &socketDescriptor = *client.m_socketDescriptor;
      assert(INVALID_SOCKET != socketDescriptor.handle);
      assert(nullptr != socketDescriptor.recvContext);
      assert(nullptr == socketDescriptor.sendContext);
      assert(nullptr == socketDescriptor.connectivityContext);
      auto &sendContext = make_data_transfer_context(m_sendContexts);
      auto bytesWritten = static_cast<size_t>(-1);
      auto errorCode = client.io_data_to_shutdown(
         data_chunk{.bytes = std::bit_cast<std::byte *>(sendContext.buffer.buf), .bytesLength = sendContext.buffer.len},
         bytesWritten
      );
      assert(errorCode || (bytesWritten != static_cast<size_t>(-1)));
      socketDescriptor.connectivityContext = std::addressof(make_disconnect_context(m_connectivityContexts));
      if (errorCode || (0 == bytesWritten))
      {
         m_sendContexts.push(sendContext);
         disconnect(client);
         return;
      }
      if (static_cast<size_t>(sendContext.buffer.len) < bytesWritten) [[unlikely]]
      {
         log_error(std::source_location::current(), "[tcp_client] written more bytes then the buffer contains: it must be a bug");
         unreachable();
      }
      sendContext.buffer.len = static_cast<ULONG>(bytesWritten);
      socketDescriptor.sendContext = std::addressof(sendContext);
      constexpr DWORD bufferCount = 1;
      DWORD bytesSent = 0;
      constexpr DWORD flags = 0;
      if (
         SOCKET_ERROR == WSASend(
            socketDescriptor.handle,
            std::addressof(sendContext.buffer),
            bufferCount,
            std::addressof(bytesSent),
            flags,
            std::addressof(sendContext.overlapped),
            nullptr
         )
      ) [[likely]]
      {
         if (
            (errorCode = check_winsock_error_if_not("[tcp_client] failed to send to TCP socket: ({}) - {}", WSA_IO_PENDING))
         ) [[unlikely]]
         {
            handle_disconnected(client, errorCode);
         }
      }
   }

   void handle_ready_to_send(tcp_client &client)
   {
      assert(nullptr != client.m_socketDescriptor);
      if (nullptr == client.m_socketDescriptor->sendContext)
      {
         send(client);
      }
   }

   void handle_recv_completion(tcp_client &client)
   {
      assert(nullptr != client.m_socketDescriptor);
      auto &socketDescriptor = *client.m_socketDescriptor;
      assert(INVALID_SOCKET != socketDescriptor.handle);
      assert(nullptr != socketDescriptor.recvContext);
      assert(nullptr == socketDescriptor.connectivityContext);
      DWORD bytesReceived = 0;
      DWORD flags = 0;
      if (
         TRUE == WSAGetOverlappedResult(
            socketDescriptor.handle,
            std::addressof(socketDescriptor.recvContext->overlapped),
            std::addressof(bytesReceived),
            FALSE,
            std::addressof(flags)
         )
      ) [[likely]]
      {
         if (0 < bytesReceived) [[likely]]
         {
            handle_received_data(client, bytesReceived);
            if ((nullptr == socketDescriptor.connectivityContext) && !socketDescriptor.disconnectReason) [[likely]]
            {
               recv(client);
            }
         }
         else
         {
            m_recvContexts.push(*socketDescriptor.recvContext);
            socketDescriptor.recvContext = nullptr;
            if (nullptr == socketDescriptor.connectivityContext)
            {
               /// Looks like connectivity issue or connection reset
               if (nullptr == socketDescriptor.sendContext)
               {
                  handle_disconnected(client, std::error_code{WSAECONNRESET, std::system_category()});
               }
               else
               {
                  /// Send operation is in progress, hope it will be completed with more details
               }
            }
            else
            {
               /// It must be a graceful shutdown, so let me wait for disconnect completion
               assert(nullptr == socketDescriptor.connectivityContext->address);
            }
         }
      }
      else
      {
         /// It must be a connectivity issue or shutdown on the peer side
         handle_disconnected(client, check_winsock_error("[tcp_client] failed to recv from TCP socket: ({}) - {}"));
      }
   }

   void handle_received_data(tcp_client &client, size_t const bytesReceived)
   {
      assert(nullptr != client.m_socketDescriptor);
      auto &socketDescriptor = *client.m_socketDescriptor;
      assert(nullptr != socketDescriptor.recvContext);
      auto &recvContext = *socketDescriptor.recvContext;
      auto &recvBuffer = recvContext.buffer;
      if (bytesReceived > recvBuffer.len) [[unlikely]]
      {
         log_error(std::source_location::current(), "[tcp_client] received more bytes then the buffer contains: it must be a bug");
         unreachable();
      }
      auto const dataTransferBuffer = WSABUF
      {
         .len = static_cast<ULONG>(m_recvContexts.object_size() - sizeof(tcp_data_transfer_context)),
         .buf = std::bit_cast<CHAR *>(socketDescriptor.recvContext + 1),
      };
      auto const totalBytesReceived = static_cast<size_t>(recvBuffer.buf - dataTransferBuffer.buf) + bytesReceived;
      size_t bytesProcessed = static_cast<size_t>(-1);
      if (
         auto const errorCode = client.io_data_received(
            data_chunk{.bytes = std::bit_cast<std::byte *>(dataTransferBuffer.buf), .bytesLength = totalBytesReceived},
            bytesProcessed
         );
         errorCode
      )
      {
         if (!socketDescriptor.disconnectReason)
         {
            socketDescriptor.disconnectReason = errorCode;
            if (nullptr == socketDescriptor.connectivityContext)
            {
               handle_ready_to_disconnect(client);
            }
         }
      }
      else if (0 == bytesProcessed)
      {
         /// Too few bytes received, let me recv some more
         recvBuffer.buf += bytesReceived;
         recvBuffer.len -= static_cast<ULONG>(bytesReceived);
         if (0 == recvBuffer.len) [[unlikely]]
         {
            log_error(std::source_location::current(), "[tcp_client] no more bytes could be received: it must be a bug");
            unreachable();
         }
      }
      else if(totalBytesReceived == bytesProcessed)
      {
         /// All received bytes were processed by the client
         recvBuffer = dataTransferBuffer;
      }
      else if (totalBytesReceived > bytesProcessed)
      {
         /// There are some extra bytes (were not processed by the client)
         auto const extraBytes = totalBytesReceived - bytesProcessed;
         MoveMemory(dataTransferBuffer.buf, dataTransferBuffer.buf + bytesProcessed, extraBytes);
         recvBuffer = WSABUF
         {
            .len = static_cast<ULONG>(dataTransferBuffer.len - extraBytes),
            .buf = dataTransferBuffer.buf + extraBytes,
         };
      }
      else [[unlikely]]
      {
         log_error(std::source_location::current(), "[tcp_client] processed more bytes then were received: it must be a bug");
         unreachable();
      }
   }

   void handle_send_completion(tcp_client &client)
   {
      assert(nullptr != client.m_socketDescriptor);
      auto &socketDescriptor = *client.m_socketDescriptor;
      assert(INVALID_SOCKET != socketDescriptor.handle);
      assert(nullptr != socketDescriptor.sendContext);
      DWORD bytesSent = 0;
      DWORD flags = 0;
      if (
         TRUE == WSAGetOverlappedResult(
            socketDescriptor.handle,
            std::addressof(socketDescriptor.sendContext->overlapped),
            std::addressof(bytesSent),
            FALSE,
            std::addressof(flags)
         )
      ) [[likely]]
      {
         assert(0 != bytesSent);
         m_sendContexts.push(*socketDescriptor.sendContext);
         socketDescriptor.sendContext = nullptr;
         if (nullptr != socketDescriptor.connectivityContext) [[unlikely]]
         {
            disconnect(client);
         }
         else if (nullptr != socketDescriptor.recvContext) [[likely]]
         {
            send(client);
         }
         else
         {
            /// Looks like connectivity issue or connection reset
            handle_disconnected(client, std::error_code{WSAECONNRESET, std::system_category()});
         }
      }
      else
      {
         /// It must be a connectivity issue or shutdown on the peer side
         handle_disconnected(client, check_winsock_error("[tcp_client] failed to send to TCP socket: ({}) - {}"));
      }
   }

   [[nodiscard]] size_t poll(DWORD const timeout)
   {
      auto const numberOfCompletionPortEntriesRemoved = m_completionPort.get_queued_completion_statuses(m_completionPortEntries, timeout);
      assert(numberOfCompletionPortEntriesRemoved <= m_completionPortEntries.size());
      auto completionPortEntry = m_completionPortEntries.begin();
      for (
         auto const completionPortEntriesEnd = completionPortEntry + numberOfCompletionPortEntriesRemoved;
         completionPortEntriesEnd != completionPortEntry;
         ++completionPortEntry
      )
      {
         handle_completion_port_entry(*completionPortEntry);
      }
      return numberOfCompletionPortEntriesRemoved;
   }

   void recv(tcp_client &client)
   {
      assert(nullptr != client.m_socketDescriptor);
      auto &socketDescriptor = *client.m_socketDescriptor;
      assert(INVALID_SOCKET != socketDescriptor.handle);
      assert(nullptr != socketDescriptor.recvContext);
      auto &recvContext = *socketDescriptor.recvContext;
      assert(nullptr != recvContext.buffer.buf);
      assert(0 < recvContext.buffer.len);
      assert(nullptr == socketDescriptor.connectivityContext);
      constexpr DWORD bufferCount = 1;
      DWORD bytesReceived = 0;
      DWORD flags = 0;
      if (
         SOCKET_ERROR == WSARecv(
            socketDescriptor.handle,
            std::addressof(recvContext.buffer),
            bufferCount,
            std::addressof(bytesReceived),
            std::addressof(flags),
            std::addressof(recvContext.overlapped),
            nullptr
         )
      ) [[likely]]
      {
         if (
            auto const errorCode = check_winsock_error_if_not("[tcp_client] failed to recv from TCP socket: ({}) - {}", WSA_IO_PENDING);
            errorCode
         ) [[unlikely]]
         {
            handle_disconnected(client, errorCode);
         }
      }
   }

   void send(tcp_client &client)
   {
      assert(nullptr != client.m_socketDescriptor);
      auto &socketDescriptor = *client.m_socketDescriptor;
      assert(INVALID_SOCKET != socketDescriptor.handle);
      assert(nullptr != socketDescriptor.recvContext);
      assert(nullptr == socketDescriptor.sendContext);
      assert(nullptr == socketDescriptor.connectivityContext);
      auto &sendContext = make_data_transfer_context(m_sendContexts);
      size_t bytesWritten = static_cast<size_t>(-1);
      if (
         auto const errorCode = client.io_data_to_send(
            data_chunk{.bytes = std::bit_cast<std::byte *>(sendContext.buffer.buf), .bytesLength = sendContext.buffer.len},
            bytesWritten
         );
         errorCode
      ) [[unlikely]]
      {
         m_sendContexts.push(sendContext);
         if (!socketDescriptor.disconnectReason)
         {
            socketDescriptor.disconnectReason = errorCode;
            handle_ready_to_disconnect(client);
         }
         return;
      }
      if (0 == bytesWritten)
      {
         m_sendContexts.push(sendContext);
         return;
      }
      if (static_cast<size_t>(sendContext.buffer.len) < bytesWritten) [[unlikely]]
      {
         log_error(std::source_location::current(), "[tcp_client] written more bytes then the buffer contains: it must be a bug");
         unreachable();
      }
      sendContext.buffer.len = static_cast<ULONG>(bytesWritten);
      socketDescriptor.sendContext = std::addressof(sendContext);
      constexpr DWORD bufferCount = 1;
      DWORD bytesSent = 0;
      constexpr DWORD flags = 0;
      if (
         SOCKET_ERROR == WSASend(
            socketDescriptor.handle,
            std::addressof(sendContext.buffer),
            bufferCount,
            std::addressof(bytesSent),
            flags,
            std::addressof(sendContext.overlapped),
            nullptr
         )
      ) [[likely]]
      {
         if (
            auto const errorCode = check_winsock_error_if_not("[tcp_client] failed to send to TCP socket: ({}) - {}", WSA_IO_PENDING);
            errorCode
         ) [[unlikely]]
         {
            handle_disconnected(client, errorCode);
         }
      }
   }

   [[nodiscard]] static std::error_code apply_socket_config(SOCKET const socket, tcp_client_config const &config)
   {
      if (true == config.keep_alive().has_value())
      {
         tcp_keep_alive const keepAlive = config.keep_alive().value();
         auto tcpKeepAlive = tcp_keepalive
         {
            .onoff = 1,
            .keepalivetime = static_cast<ULONG>(std::chrono::duration_cast<std::chrono::milliseconds>(keepAlive.idleTimeout).count()),
            .keepaliveinterval = static_cast<ULONG>(std::chrono::duration_cast<std::chrono::milliseconds>(keepAlive.probeTimeout).count()),
         };
         DWORD bytesReturned = 0;
         if (
            SOCKET_ERROR == WSAIoctl(
               socket,
               SIO_KEEPALIVE_VALS,
               std::addressof(tcpKeepAlive),
               sizeof(tcpKeepAlive),
               nullptr,
               0,
               std::addressof(bytesReturned),
               nullptr,
               nullptr
            )
         ) [[unlikely]]
         {
            return check_winsock_error("[tcp_client] failed to set SIO_KEEPALIVE_VALS socket option: ({}) - {}");
         }
#if (defined(TCP_KEEPCNT))
         DWORD const keepAliveProbesCount = keepAlive.probesCount;
         if (
            SOCKET_ERROR == setsockopt(
               socket,
               IPPROTO_TCP,
               TCP_KEEPCNT,
               std::bit_cast<char const *>(std::addressof(keepAliveProbesCount)),
               sizeof(keepAliveProbesCount)
            )
         ) [[unlikely]]
         {
            return check_winsock_error("[tcp_client] failed to set TCP_KEEPCNT socket option: ({}) - {}");
         }
#endif
      }
      if (true == config.nodelay())
      {
         DWORD const nodelay = TRUE;
         if (
            SOCKET_ERROR == setsockopt(
               socket,
               IPPROTO_TCP,
               TCP_NODELAY,
               std::bit_cast<char const *>(std::addressof(nodelay)),
               sizeof(nodelay)
            )
         ) [[unlikely]]
         {
            return check_winsock_error("[tcp_client] failed to set TCP_NODELAY socket option: ({}) - {}");
         }
      }
      SOCKET_ADDRESS interfaceAddress = {.lpSockaddr = nullptr, .iSockaddrLength = 0};
      SOCKADDR_INET bindAddress = {.si_family = config.peer_address().socket_address()->sockaddr().si_family};
      if (true == config.peer_address().network_interface().has_value())
      {
         auto const &networkInterface = config.peer_address().network_interface().value();
         if (AF_INET == bindAddress.si_family)
         {
            if (true == networkInterface.ip_v4().has_value()) [[likely]]
            {
               auto const &sockaddr = networkInterface.ip_v4().value()->sockaddr();
               interfaceAddress.lpSockaddr = std::bit_cast<LPSOCKADDR>(std::addressof(sockaddr.Ipv4));
               interfaceAddress.iSockaddrLength = sizeof(sockaddr.Ipv4);
            }
            else
            {
               log_error(
                  std::source_location::current(),
                  "[tcp_client] interface has no IPv4 address: {}",
                  networkInterface.friendly_name()
               );
               unreachable();
            }
         }
         else if (AF_INET6 == bindAddress.si_family)
         {
            if (true == networkInterface.ip_v6().has_value()) [[likely]]
            {
               auto const &sockaddr = networkInterface.ip_v6().value()->sockaddr();
               interfaceAddress.lpSockaddr = std::bit_cast<LPSOCKADDR>(std::addressof(sockaddr.Ipv6));
               interfaceAddress.iSockaddrLength = sizeof(sockaddr.Ipv6);
            }
            else
            {
               log_error(
                  std::source_location::current(),
                  "[tcp_client] interface has no IPv6 address: {}",
                  networkInterface.friendly_name()
               );
               unreachable();
            }
         }
         else [[unlikely]]
         {
            log_error(
               std::source_location::current(),
               "[tcp_client] unexpected address family: {}",
               bindAddress.si_family
            );
            unreachable();
         }
      }
      else
      {
         interfaceAddress.lpSockaddr = std::bit_cast<LPSOCKADDR>(std::addressof(bindAddress));
         if (AF_INET == bindAddress.si_family)
         {
            bindAddress.Ipv4.sin_addr = in4addr_any;
            interfaceAddress.iSockaddrLength = sizeof(bindAddress.Ipv4);
         }
         else if (AF_INET6 == bindAddress.si_family)
         {
            bindAddress.Ipv6.sin6_addr = in6addr_any;
            interfaceAddress.iSockaddrLength = sizeof(bindAddress.Ipv6);
         }
         else [[unlikely]]
         {
            log_error(
               std::source_location::current(),
               "[tcp_client] unexpected address family: {}",
               bindAddress.si_family
            );
            unreachable();
         }
      }
      if (SOCKET_ERROR == bind(socket, interfaceAddress.lpSockaddr, interfaceAddress.iSockaddrLength)) [[unlikely]]
      {
         return check_winsock_error("[tcp_client] failed to bind TCP socket to the network interface: ({}) - {}");
      }
      if (std::chrono::milliseconds::zero() < config.user_timeout())
      {
         auto initialRtoParameters = TCP_INITIAL_RTO_PARAMETERS
         {
            .Rtt = static_cast<USHORT>(std::chrono::duration_cast<std::chrono::milliseconds>(config.user_timeout()).count()),
            .MaxSynRetransmissions = 1,
         };
         if (
            DWORD bytesReturned = 0;
            SOCKET_ERROR == WSAIoctl(
               socket,
               SIO_TCP_INITIAL_RTO,
               std::addressof(initialRtoParameters),
               sizeof(initialRtoParameters),
               nullptr,
               0,
               std::addressof(bytesReturned),
               nullptr,
               nullptr
            )
         ) [[unlikely]]
         {
            return check_winsock_error("[tcp_client] failed to set SIO_TCP_INITIAL_RTO socket option: ({}) - {}");
         }
      }
#if (defined(TCP_FAIL_CONNECT_ON_ICMP_ERROR))
      if (SOCKET_ERROR == WSASetFailConnectOnIcmpError(socket, TRUE))
      {
         check_winsock_error("[tcp_client] failed to set TCP_FAIL_CONNECT_ON_ICMP_ERROR socket option: ({}) - {}");
      }
#endif
      return {};
   }

   template<typename extension_function>
   [[nodiscard]] static int get_extension_function_pointer(
      SOCKET const socket,
      GUID functionId,
      extension_function &functionPointer
   ) noexcept
   {
      DWORD bytesReturned = 0;
      return WSAIoctl(
         socket,
         SIO_GET_EXTENSION_FUNCTION_POINTER,
         std::addressof(functionId),
         sizeof(functionId),
         std::addressof(functionPointer),
         sizeof(extension_function),
         std::addressof(bytesReturned),
         nullptr,
         nullptr
      );
   }

   [[nodiscard]] static tcp_connectivity_context &make_connect_context(object_pool<tcp_connectivity_context> &connectivityContexts)
   {
      auto &connectivityContext = connectivityContexts.pop();
      connectivityContext.address = std::bit_cast<SOCKADDR *>(std::addressof(connectivityContext) + 1);
      return connectivityContext;
   }

   [[nodiscard]] static tcp_data_transfer_context &make_data_transfer_context(object_pool<tcp_data_transfer_context> &dataTransferContexts)
   {
      auto const dataTransferContextSize = dataTransferContexts.object_size();
      assert(sizeof(tcp_data_transfer_context) < dataTransferContextSize);
      auto &dataTransferContext = dataTransferContexts.pop();
      dataTransferContext.buffer.len = static_cast<ULONG>(dataTransferContextSize - sizeof(tcp_data_transfer_context));
      dataTransferContext.buffer.buf = std::bit_cast<CHAR *>(std::addressof(dataTransferContext) + 1);
      return dataTransferContext;
   }

   [[nodiscard]] static tcp_connectivity_context &make_disconnect_context(object_pool<tcp_connectivity_context> &connectivityContexts)
   {
      return connectivityContexts.pop();
   }
};

}
