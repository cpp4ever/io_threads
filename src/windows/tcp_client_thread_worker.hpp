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

#include "completion_port.hpp" ///< for io_threads::completion_port
#include "logger.hpp" ///< for io_threads::log_error
#include "object_pool.hpp" ///< for io_threads::object_pool
#include "socket_address_impl.hpp" ///< for io_threads::socket_address::socket_address_impl
#include "tcp_client_command.hpp" ///< for io_threads::tcp_client_command, io_threads::from_completion_overlapped
#include "tcp_connectivity_context.hpp" ///< for io_threads::tcp_connectivity_context
/// for
///   io_threads::tcp_data_transfer_context,
///   io_threads::wsabuf_from_data_chunk,
///   io_threads::wsabuf_to_data_chunk
#include "tcp_data_transfer_context.hpp"
#include "tcp_socket_descriptor.hpp" ///< for io_threads::tcp_socket_descriptor
#include "utility.hpp" ///< for io_threads::to_underlying, io_threads::unreachable
#include "winsock_error.hpp" ///< for io_threads::check_winsock_error, io_threads::check_winsock_error_if_not

#include "io_threads/network_interface.hpp" ///< for io_threads::network_interface
#include "io_threads/tcp_client.hpp" ///< for io_threads::tcp_client_thread::tcp_client
#include "io_threads/tcp_client_config.hpp" ///< for io_threads::tcp_client_config
#include "io_threads/tcp_client_thread.hpp" ///< for io_threads::tcp_client_thread::tcp_client_impl

/// for
///   AF_INET,
///   AF_INET6,
///   bind,
///   closesocket,
///   DWORD,
///   ERROR_SUCCESS,
///   FALSE,
///   INVALID_SOCKET,
///   IPPROTO_TCP,
///   LPSOCKADDR,
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
#include <future> ///< for std::promise
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
      size_t const sendBufferSize,
      std::promise<completion_port const &> &completionPortPromise
   ) :
      m_socketDescriptors{initialCapacityOfSocketDescriptors},
      m_recvContexts{initialCapacityOfSocketDescriptors, sizeof(tcp_data_transfer_context) + recvBufferSize},
      m_sendContexts{initialCapacityOfSocketDescriptors, sizeof(tcp_data_transfer_context) + sendBufferSize},
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
         check_winsock_error("[io_threads] failed to create TCP socket: ({}) - {}");
         unreachable();
      }
      if (SOCKET_ERROR == get_extension_function_pointer(socket, WSAID_CONNECTEX, m_connect))
      {
         check_winsock_error("[io_threads] failed to get ConnectEx extension function pointer: ({}) - {}");
         unreachable();
      }
      if (SOCKET_ERROR == get_extension_function_pointer(socket, WSAID_DISCONNECTEX, m_disconnect))
      {
         check_winsock_error("[io_threads] failed to get DisconnectEx extension function pointer: ({}) - {}");
         unreachable();
      }
      if (SOCKET_ERROR == closesocket(socket))
      {
         check_winsock_error("[io_threads] failed to close TCP socket: ({}) - {}");
      }
      completionPortPromise.set_value(m_completionPort);
   }

   tcp_client_thread_worker &operator = (tcp_client_thread_worker &&) = delete;
   tcp_client_thread_worker &operator = (tcp_client_thread_worker const &) = delete;

   void run(std::stop_token const stopToken)
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

private:
   completion_port m_completionPort = {};
   completion_port::entries m_completionPortEntries = {};
   LPFN_CONNECTEX m_connect = nullptr;
   LPFN_DISCONNECTEX m_disconnect = nullptr;
   object_pool<tcp_socket_descriptor> m_socketDescriptors;
   object_pool<tcp_data_transfer_context> m_recvContexts;
   object_pool<tcp_data_transfer_context> m_sendContexts;
   object_pool<tcp_connectivity_context> m_connectivityContexts;

   void close_socket(tcp_client &client)
   {
      assert(nullptr != client.m_socketDescriptor);
      auto &socketDescriptor = *client.m_socketDescriptor;
      assert(INVALID_SOCKET != socketDescriptor.handle);
      if (SOCKET_ERROR == closesocket(socketDescriptor.handle)) [[unlikely]]
      {
         check_winsock_error("[io_threads] failed to close TCP socket: ({}) - {}");
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
      m_socketDescriptors.push(socketDescriptor);
      client.m_socketDescriptor = nullptr;
   }

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
            auto const errorCode = check_winsock_error_if_not("[io_threads] failed to connect TCP socket: ({}) - {}", WSA_IO_PENDING);
            errorCode
         ) [[unlikely]]
         {
            close_socket(client);
            client.io_disconnected(errorCode);
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
               "[io_threads] unexpected completion overlapped: it must be a bug"
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
            check_winsock_error("[io_threads] failed to set SO_UPDATE_CONNECT_CONTEXT socket option: ({}) - {}");
         }
         socketDescriptor.recvContext = std::addressof(make_data_transfer_context(m_recvContexts));
         m_connectivityContexts.push(*socketDescriptor.connectivityContext);
         socketDescriptor.connectivityContext = nullptr;
         recv(client);
         send(client);
      }
      else
      {
         /// It must be a connectivity issue or shutdown on the peer side
         auto const errorCode = check_winsock_error("[io_threads] failed to connect TCP socket: ({}) - {}");
         if (std::error_code{WSAEHOSTUNREACH, std::generic_category()} == errorCode)
         {
            ICMP_ERROR_INFO icmpErrorInfo = {};
            if (SOCKET_ERROR != WSAGetIcmpErrorInfo(socketDescriptor.handle, std::addressof(icmpErrorInfo)))
            {
               socket_address::socket_address_impl socketAddress{icmpErrorInfo.srcaddress};
               log_error(
                  std::source_location::current(),
                  "[io_threads] ICMP error info: srcaddress={} protocol={} type={} code={}",
                  std::string_view{socketAddress},
                  to_underlying(icmpErrorInfo.protocol),
                  icmpErrorInfo.type,
                  icmpErrorInfo.code
               );
            }
         }
         close_socket(client);
         client.io_disconnected(errorCode);
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
         check_winsock_error("[io_threads] failed to disconnect TCP socket: ({}) - {}");
      }
      close_socket(client);
      client.io_disconnected(std::error_code{});
   }

   void handle_ready_to_connect(tcp_client &client)
   {
      assert(nullptr == client.m_socketDescriptor);
      auto const config = client.io_ready_to_connect();
      auto const &socketAddress = config.peer_address().socket_address().get().sockaddr();
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
               check_winsock_error("[io_threads] failed to close TCP socket: ({}) - {}");
            }
            client.io_disconnected(errorCode);
         }
         else
         {
            auto &connectivityContext = make_connect_context(m_connectivityContexts);
            assert(nullptr != connectivityContext.address);
            std::memcpy(
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
         client.io_disconnected(check_winsock_error("[io_threads] failed to create TCP socket: ({}) - {}"));
      }
   }

   void handle_ready_to_disconnect(tcp_client &client)
   {
      assert(nullptr != client.m_socketDescriptor);
      auto &socketDescriptor = *client.m_socketDescriptor;
      assert(INVALID_SOCKET != socketDescriptor.handle);
      assert(nullptr == socketDescriptor.sendContext);
      assert(nullptr == socketDescriptor.connectivityContext);
      assert(nullptr != m_disconnect);
      socketDescriptor.connectivityContext = std::addressof(make_disconnect_context(m_connectivityContexts));
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
            auto const errorCode = check_winsock_error_if_not("[io_threads] failed to disconnect TCP socket: ({}) - {}", WSA_IO_PENDING);
            errorCode
         ) [[unlikely]]
         {
            close_socket(client);
            client.io_disconnected(errorCode);
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
      DWORD bytesRecvd = 0;
      DWORD flags = 0;
      if (
         TRUE == WSAGetOverlappedResult(
            socketDescriptor.handle,
            std::addressof(socketDescriptor.recvContext->overlapped),
            std::addressof(bytesRecvd),
            FALSE,
            std::addressof(flags)
         )
      ) [[likely]]
      {
         if (0 < bytesRecvd) [[likely]]
         {
            client.io_recv(wsabuf_to_data_chunk(socketDescriptor.recvContext->buffer, bytesRecvd));
            recv(client);
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
                  close_socket(client);
                  client.io_disconnected(std::error_code{WSAECONNRESET, std::system_category()});
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
         auto const errorCode = check_winsock_error("[io_threads] failed to recv from TCP socket: ({}) - {}");
         close_socket(client);
         client.io_disconnected(errorCode);
      }
   }

   void handle_send_completion(tcp_client &client)
   {
      assert(nullptr != client.m_socketDescriptor);
      auto &socketDescriptor = *client.m_socketDescriptor;
      assert(INVALID_SOCKET != socketDescriptor.handle);
      assert(nullptr != socketDescriptor.sendContext);
      assert(nullptr == socketDescriptor.connectivityContext);
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
         if (nullptr != socketDescriptor.recvContext) [[likely]]
         {
            send(client);
         }
         else if (nullptr == socketDescriptor.connectivityContext)
         {
            /// Looks like connectivity issue or connection reset
            close_socket(client);
            client.io_disconnected(std::error_code{WSAECONNRESET, std::system_category()});
         }
         else
         {
            /// It must be a graceful shutdown, so let me wait for disconnect completion
            assert(nullptr == socketDescriptor.connectivityContext->address);
         }
      }
      else
      {
         /// It must be a connectivity issue or shutdown on the peer side
         auto const errorCode = check_winsock_error("[io_threads] failed to send to TCP socket: ({}) - {}");
         close_socket(client);
         client.io_disconnected(errorCode);
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
      assert(nullptr == socketDescriptor.connectivityContext);
      constexpr DWORD bufferCount = 1;
      DWORD bytesRecvd = 0;
      DWORD flags = 0;
      if (
         SOCKET_ERROR == WSARecv(
            socketDescriptor.handle,
            std::addressof(socketDescriptor.recvContext->buffer),
            bufferCount,
            std::addressof(bytesRecvd),
            std::addressof(flags),
            std::addressof(socketDescriptor.recvContext->overlapped),
            nullptr
         )
      ) [[likely]]
      {
         if (
            auto const errorCode = check_winsock_error_if_not("[io_threads] failed to connect TCP socket: ({}) - {}", WSA_IO_PENDING);
            errorCode
         ) [[unlikely]]
         {
            close_socket(client);
            client.io_disconnected(errorCode);
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
      socketDescriptor.sendContext = std::addressof(make_data_transfer_context(m_sendContexts));
      auto const dataChunk = client.io_ready_to_send(wsabuf_to_data_chunk(socketDescriptor.sendContext->buffer));
      if (0 == dataChunk.size)
      {
         m_sendContexts.push(*socketDescriptor.sendContext);
         socketDescriptor.sendContext = nullptr;
         return;
      }
      assert(nullptr != dataChunk.data);
      socketDescriptor.sendContext->buffer = wsabuf_from_data_chunk(dataChunk);
      constexpr DWORD bufferCount = 1;
      DWORD bytesSent = 0;
      constexpr DWORD flags = 0;
      if (
         SOCKET_ERROR == WSASend(
            socketDescriptor.handle,
            std::addressof(socketDescriptor.sendContext->buffer),
            bufferCount,
            std::addressof(bytesSent),
            flags,
            std::addressof(socketDescriptor.sendContext->overlapped),
            nullptr
         )
      ) [[likely]]
      {
         if (
            auto const errorCode = check_winsock_error_if_not("[io_threads] failed to connect TCP socket: ({}) - {}", WSA_IO_PENDING);
            errorCode
         ) [[unlikely]]
         {
            close_socket(client);
            client.io_disconnected(errorCode);
         }
      }
   }

   [[nodiscard]] static std::error_code apply_socket_config(SOCKET const socket, tcp_client_config const &config)
   {
      if (true == config.keep_alive().has_value())
      {
         DWORD const enableKeepAlive = TRUE;
         if (
            SOCKET_ERROR == setsockopt(
               socket,
               SOL_SOCKET,
               SO_KEEPALIVE,
               std::bit_cast<char const *>(std::addressof(enableKeepAlive)),
               sizeof(enableKeepAlive)
            )
         ) [[unlikely]]
         {
            return check_winsock_error("[io_threads] failed to set SO_KEEPALIVE socket option: ({}) - {}");
         }
         tcp_keep_alive const keepAlive = config.keep_alive().value();
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
            return check_winsock_error("[io_threads] failed to set TCP_KEEPCNT socket option: ({}) - {}");
         }
         auto const keepAliveIdleTimeout = static_cast<DWORD>(keepAlive.idleTimeout.count());
         if (
            SOCKET_ERROR == setsockopt(
               socket,
               IPPROTO_TCP,
               TCP_KEEPIDLE,
               std::bit_cast<char const *>(std::addressof(keepAliveIdleTimeout)),
               sizeof(keepAliveIdleTimeout)
            )
         ) [[unlikely]]
         {
            return check_winsock_error("[io_threads] failed to set TCP_KEEPIDLE socket option: ({}) - {}");
         }
         auto const keepAliveProbeTimeout = static_cast<DWORD>(keepAlive.probeTimeout.count());
         if (
            SOCKET_ERROR == setsockopt(
               socket,
               IPPROTO_TCP,
               TCP_KEEPINTVL,
               std::bit_cast<char const *>(std::addressof(keepAliveProbeTimeout)),
               sizeof(keepAliveProbeTimeout)
            )
         ) [[unlikely]]
         {
            return check_winsock_error("[io_threads] failed to set TCP_KEEPINTVL socket option: ({}) - {}");
         }
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
            return check_winsock_error("[io_threads] failed to set TCP_NODELAY socket option: ({}) - {}");
         }
      }
      SOCKET_ADDRESS interfaceAddress = {.lpSockaddr = nullptr, .iSockaddrLength = 0};
      SOCKADDR_INET bindAddress = {.si_family = config.peer_address().socket_address().get().sockaddr().si_family};
      if (true == config.peer_address().network_interface().has_value())
      {
         auto const &networkInterface = config.peer_address().network_interface().value();
         if (AF_INET == bindAddress.si_family)
         {
            if (true == networkInterface.ip_v4().has_value()) [[likely]]
            {
               auto const &sockaddr = networkInterface.ip_v4().value().get().sockaddr();
               interfaceAddress.lpSockaddr = std::bit_cast<LPSOCKADDR>(std::addressof(sockaddr.Ipv4));
               interfaceAddress.iSockaddrLength = sizeof(sockaddr.Ipv4);
            }
            else
            {
               log_error(
                  std::source_location::current(),
                  "[io_threads] interface has no IPv4 address: {}",
                  networkInterface.friendly_name()
               );
               unreachable();
            }
         }
         else if (AF_INET6 == bindAddress.si_family)
         {
            if (true == networkInterface.ip_v6().has_value()) [[likely]]
            {
               auto const &sockaddr = networkInterface.ip_v6().value().get().sockaddr();
               interfaceAddress.lpSockaddr = std::bit_cast<LPSOCKADDR>(std::addressof(sockaddr.Ipv6));
               interfaceAddress.iSockaddrLength = sizeof(sockaddr.Ipv6);
            }
            else
            {
               log_error(
                  std::source_location::current(),
                  "[io_threads] interface has no IPv6 address: {}",
                  networkInterface.friendly_name()
               );
               unreachable();
            }
         }
         else [[unlikely]]
         {
            log_error(
               std::source_location::current(),
               "[io_threads] unexpected address family: {}",
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
               "[io_threads] unexpected address family: {}",
               bindAddress.si_family
            );
            unreachable();
         }
      }
      if (SOCKET_ERROR == bind(socket, interfaceAddress.lpSockaddr, interfaceAddress.iSockaddrLength)) [[unlikely]]
      {
         return check_winsock_error("[io_threads] failed to bind TCP socket to the network interface: ({}) - {}");
      }
      if (std::chrono::milliseconds::zero() < config.user_timeout())
      {
         auto const retransmitTimeout = std::max<DWORD>(1, static_cast<DWORD>(std::chrono::round<std::chrono::seconds>(config.user_timeout()).count()));
         if (
            SOCKET_ERROR == setsockopt(
               socket,
               IPPROTO_TCP,
               TCP_MAXRT,
               std::bit_cast<char const *>(std::addressof(retransmitTimeout)),
               sizeof(retransmitTimeout)
            )
         ) [[unlikely]]
         {
            return check_winsock_error("[io_threads] failed to set TCP_MAXRT socket option: ({}) - {}");
         }
      }
      if (SOCKET_ERROR == WSASetFailConnectOnIcmpError(socket, TRUE))
      {
         check_winsock_error("[io_threads] failed to set TCP_FAIL_CONNECT_ON_ICMP_ERROR socket option: ({}) - {}");
      }
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
      assert(sizeof(tcp_data_transfer_context) <= dataTransferContextSize);
      auto &dataTransferContext = dataTransferContexts.pop();
      if (sizeof(tcp_data_transfer_context) < dataTransferContextSize)
      {
         dataTransferContext.buffer.len = static_cast<ULONG>(dataTransferContextSize - sizeof(tcp_data_transfer_context));
         dataTransferContext.buffer.buf = std::bit_cast<CHAR *>(std::addressof(dataTransferContext) + 1);
      }
      return dataTransferContext;
   }

   [[nodiscard]] static tcp_connectivity_context &make_disconnect_context(object_pool<tcp_connectivity_context> &connectivityContexts)
   {
      return connectivityContexts.pop();
   }
};

}
