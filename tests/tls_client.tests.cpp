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

#include "tcp/test_tcp_certificate.hpp"
#include "tcp/test_tcp_common.hpp" ///< for test_keep_alive_delay, test_peer_ssl_port
#include "tcp/test_tcp_server_context.hpp"
#include "tcp/rest/test_rest_client.hpp" ///< for test_rest_client, test_rest_client_traits
#include "testsuite.hpp"

#include <boost/beast.hpp> ///< for boost::beast::tcp_stream
#include <gmock/gmock.h> ///< for EXPECT_CALL, MOCK_METHOD, testing::Return, testing::StrictMock, testing::_
#include <gtest/gtest.h> ///< for TEST
#include <io_threads/dns_resolver.hpp> ///< for io_threads::dns_resolver
#include <io_threads/tls_client.hpp> ///< for io_threads::tls_client

#include <cstdint> ///< for uint16_t
#include <string_view> ///< for std::string_view

namespace io_threads::tests
{

class tls_client_mock : public io_threads::tls_client
{
private:
   struct internal_state final
   {
      std::atomic_bool asleep = false;
      std::promise<void> done = {};
      std::future<void> doneFuture = done.get_future();
   };

public:
   using tls_client::tls_client;

   tls_client_mock &operator = (tls_client_mock &&) = delete;
   tls_client_mock &operator = (tls_client_mock const &) = delete;

   void expect_disconnect()
   {
      expect_error(testing::AnyOf(std::error_code{}));
      ready_to_disconnect();
   }

   template<typename error_code_matcher>
   void expect_error(error_code_matcher &&errorCodeMatcher)
   {
      EXPECT_CALL(*this, io_disconnected(testing::_))
         .WillOnce(
            [this, errorCodeMatcher] (auto const errorCode)
            {
               EXPECT_THAT(errorCode, errorCodeMatcher) << errorCode.value() << ": " << errorCode.message();
               EXPECT_CALL(*this, io_data_decrypted(testing::_, testing::_)).Times(0);
               EXPECT_CALL(*this, io_data_to_encrypt(testing::_, testing::_)).Times(0);
               EXPECT_CALL(*this, io_disconnected(testing::_)).Times(0);
               EXPECT_CALL(*this, io_ready_to_connect()).Times(0);
               assert(nullptr != m_internalState);
               m_internalState->asleep.store(false, std::memory_order_relaxed);
               m_internalState->done.set_value();
            }
         )
      ;
   }

   template<typename error_code_matcher>
   void expect_error_on_send(std::string const &message, error_code_matcher &&errorCodeMatcher)
   {
      EXPECT_CALL(*this, io_data_to_encrypt(testing::_, testing::_))
         .WillRepeatedly(
            [this, message] (auto *bytes, auto const bytesLength)
            {
               EXPECT_CALL(*this, io_data_to_encrypt(testing::_, testing::_)).WillRepeatedly(
                  [this] (auto *, auto)
                  {
                     EXPECT_CALL(*this, io_data_to_encrypt(testing::_, testing::_)).Times(0);
                     assert(nullptr != m_internalState);
                     m_internalState->asleep.store(true, std::memory_order_release);
                     return 0;
                  }
               );
               assert(message.size() <= bytesLength);
               std::memcpy(bytes, message.data(), message.size());
               return message.size();
            }
         )
      ;
      expect_error(errorCodeMatcher);
      if (
         (nullptr != m_internalState) &&
         (true == m_internalState->asleep.exchange(false, std::memory_order_acq_rel))
      )
      {
         ready_to_send();
      }
   }

   void expect_ready_to_connect(tcp_client_config const &testConfig)
   {
      m_internalState = std::make_unique<internal_state>();
      EXPECT_CALL(*this, io_ready_to_connect()).WillOnce(testing::Return(testConfig));
      ready_to_connect();
   }

   void expect_ready_to_send(std::string const &message)
   {
      EXPECT_CALL(*this, io_data_to_encrypt(testing::_, testing::_))
         .WillOnce(
            [this, message] (auto *bytes, auto const bytesLength)
            {
               EXPECT_CALL(*this, io_data_to_encrypt(testing::_, testing::_)).WillOnce(
                  [this] (auto *, auto)
                  {
                     assert(nullptr != m_internalState);
                     m_internalState->asleep.store(true, std::memory_order_release);
                     return 0;
                  }
               );
               assert(message.size() <= bytesLength);
               std::memcpy(bytes, message.data(), message.size());
               return message.size();
            }
         )
      ;
      if (
         (nullptr != m_internalState) &&
         (true == m_internalState->asleep.exchange(false, std::memory_order_acq_rel))
      )
      {
         ready_to_send();
      }
   }

   template<typename recv_handler>
   void expect_recv(recv_handler &&recvHandler)
   {
      EXPECT_CALL(*this, io_data_decrypted(testing::_, testing::_))
         .WillOnce(
            [this, recvHandler] (auto const *bytes, auto const bytesLength)
            {
               recvHandler(bytes, bytesLength);
            }
         )
      ;
   }

   template<typename recv_handler>
   void expect_recv(std::string const &message, recv_handler &&recvHandler)
   {
      m_receivedMessage.clear();
      m_receivedMessage.reserve(message.size() + 1);
      EXPECT_CALL(*this, io_data_decrypted(testing::_, testing::_))
         .WillOnce(
            [this, message, recvHandler] (auto const *bytes, auto const bytesLength)
            {
               m_receivedMessage.append(
                  std::bit_cast<char const *>(bytes),
                  std::min(bytesLength, message.size() - m_receivedMessage.size())
               );
               if (m_receivedMessage.size() < message.size())
               {
                  return;
               }
               assert(m_receivedMessage.size() == message.size());
               EXPECT_EQ(m_receivedMessage, message);
               recvHandler();
            }
         )
      ;
   }

   auto wait_for(std::chrono::seconds const timeout) const
   {
      assert(nullptr != m_internalState);
      return m_internalState->doneFuture.wait_for(timeout);
   }

private:
   std::string m_receivedMessage = {};
   std::unique_ptr<internal_state> m_internalState = {};

   MOCK_METHOD(void, io_data_decrypted, (std::byte const *bytes, size_t bytesCapacity), (final));
   MOCK_METHOD(size_t, io_data_to_encrypt, (std::byte *bytes, size_t bytesCapacity), (final));
   MOCK_METHOD(void, io_disconnected, (std::error_code errorCode), (final));
   MOCK_METHOD(tcp_client_config, io_ready_to_connect, (), (final));
};

using test_tls_client = testing::StrictMock<tls_client_mock>;

using tls_client = testsuite;

constexpr size_t test_connections_capacity = 0;

TEST(tls_client, https)
{
   constexpr size_t testRecvBufferSize = 4 * 1024;
   constexpr size_t testSendBufferSize = 4 * 1024;
   auto const testThread = io_threads::tcp_client_thread
   {
      test_cpu_id,
      test_connections_capacity,
      testRecvBufferSize,
      testSendBufferSize
   };
   auto testTlsContext = tls_client_context
   {
      test_domain,
      ssl_certificate{test_certificate_p12(), ssl_certificate_type::p12},
      0,
   };
   auto testClient = test_tls_client{testThread, testTlsContext};
   test_rest_client<test_tls_stream>(testClient, test_peer_ssl_port);
}

struct test_host_port final
{
   std::string_view host = {};
   uint16_t port = 443;
};

struct test_host_port_error_code final
{
   std::string_view host = {};
   uint16_t port = 443;
   std::error_code errorCode = {};
};

TEST(tls_client, badssl)
{
#if (defined(_WIN32) || defined(_WIN64))
   auto const testCertificateExpiredErrorCode = std::error_code{SEC_E_CERT_EXPIRED, std::system_category()};
   auto const testWrongHostErrorCode = std::error_code{SEC_E_WRONG_PRINCIPAL, std::system_category()};
   auto const testUntrustedRootErrorCode = std::error_code{SEC_E_UNTRUSTED_ROOT, std::system_category()};
   auto const testIllegalMessageErrorCode = std::error_code{SEC_E_ILLEGAL_MESSAGE, std::system_category()};
   auto const testAlgorithmMismatchErrorCode = std::error_code{SEC_E_ALGORITHM_MISMATCH, std::system_category()};
#endif
   auto const testBadAddresses = std::to_array(
      {
         /// https://badssl.com/dashboard/
         /// Certificate Validation (High Risk)
         test_host_port_error_code{.host = "expired.badssl.com", .errorCode = testCertificateExpiredErrorCode},
         test_host_port_error_code{.host = "wrong.host.badssl.com", .errorCode = testWrongHostErrorCode},
         test_host_port_error_code{.host = "self-signed.badssl.com", .errorCode = testUntrustedRootErrorCode},
         test_host_port_error_code{.host = "untrusted-root.badssl.com", .errorCode = testUntrustedRootErrorCode},
         /// Interception Certificates (High Risk)
         test_host_port_error_code{.host = "superfish.badssl.com", .errorCode = testUntrustedRootErrorCode},
         test_host_port_error_code{.host = "edellroot.badssl.com", .errorCode = testUntrustedRootErrorCode},
         test_host_port_error_code{.host = "dsdtestprovider.badssl.com", .errorCode = testUntrustedRootErrorCode},
         test_host_port_error_code{.host = "preact-cli.badssl.com", .errorCode = testUntrustedRootErrorCode},
         test_host_port_error_code{.host = "webpack-dev-server.badssl.com", .errorCode = testUntrustedRootErrorCode},
         /// Broken Cryptography (Medium Risk)
         test_host_port_error_code{.host = "rc4.badssl.com", .errorCode = testIllegalMessageErrorCode},
         test_host_port_error_code{.host = "rc4-md5.badssl.com", .errorCode = testIllegalMessageErrorCode},
         test_host_port_error_code{.host = "dh480.badssl.com", .errorCode = testIllegalMessageErrorCode},
         test_host_port_error_code{.host = "dh512.badssl.com", .errorCode = testIllegalMessageErrorCode},
         test_host_port_error_code{.host = "dh1024.badssl.com", .errorCode = testIllegalMessageErrorCode},
         test_host_port_error_code{.host = "null.badssl.com", .errorCode = testIllegalMessageErrorCode},
         /// Legacy Cryptography (Moderate Risk)
         test_host_port_error_code{.host = "tls-v1-0.badssl.com", .port = 1010, .errorCode = testAlgorithmMismatchErrorCode},
         test_host_port_error_code{.host = "tls-v1-1.badssl.com", .port = 1011, .errorCode = testAlgorithmMismatchErrorCode},
         test_host_port_error_code{.host = "3des.badssl.com", .errorCode = testIllegalMessageErrorCode},
         test_host_port_error_code{.host = "dh2048.badssl.com", .errorCode = testIllegalMessageErrorCode},
#if (not defined(_WIN32) && not defined(_WIN64))
         /// Domain Security Policies
         test_host_port_error_code{.host = "revoked.badssl.com"}, ///< The leaf certificate for this site has been revoked
         test_host_port_error_code{.host = "pinning-test.badssl.com"}, ///< This site is preloaded with a bad HPKP pin starting in Chrome 48
         test_host_port_error_code{.host = "no-sct.badssl.com"}, ///< The server does not send a Signed Certificate Timestamp (SCT) for this domain
#endif
         /// https://clienttest.ssllabs.com:8443/ssltest/viewMyClient.html
         /// CVE-2020-0601 (CurveBall) Vulnerability
         test_host_port_error_code{.host = "www.ssllabs.com", .port = 10446, .errorCode = testUntrustedRootErrorCode},
         /// Logjam Vulnerability
         test_host_port_error_code{.host = "www.ssllabs.com", .port = 10445, .errorCode = testIllegalMessageErrorCode},
         /// FREAK Vulnerability
         test_host_port_error_code{.host = "www.ssllabs.com", .port = 10444, .errorCode = testAlgorithmMismatchErrorCode},
      }
   );
   constexpr size_t testRecvBufferSize = 24 * 1024;
   constexpr size_t testSendBufferSize = 24 * 1024;
   auto const testThread = io_threads::tcp_client_thread
   {
      test_cpu_id,
      test_connections_capacity,
      testRecvBufferSize,
      testSendBufferSize
   };
   for (auto const &testBadAddress : testBadAddresses)
   {
      auto testIPv4Addresses = dns_resolver::resolve_ipv4(testBadAddress.host, testBadAddress.port);
      ASSERT_FALSE(testIPv4Addresses.empty());
      auto testTlsContext = tls_client_context{testBadAddress.host, 0};
      auto testClient = test_tls_client{testThread, testTlsContext};
      testClient.expect_error_on_send(
         std::format("GET / HTTP/1.1\r\nHost:{}\r\nAccept:*/*\r\n\r\n", testBadAddress.host),
         testing::AnyOf(testBadAddress.errorCode)
      );
      auto const testClientConfig =
         tcp_client_config{tcp_client_address{testIPv4Addresses.front()}}
         .with_keep_alive(
            tcp_keep_alive
            {
               .idleTimeout = test_keep_alive_delay,
               .probeTimeout = test_keep_alive_delay,
               .probesCount = 0
            }
         )
         .with_nodelay()
         .with_user_timeout(test_good_request_timeout * 5)
      ;
      testClient.expect_ready_to_connect(testClientConfig);
      ASSERT_EQ(std::future_status::ready, testClient.wait_for(test_good_request_timeout * 10)) << testBadAddress.host;
   }
}

TEST(tls_client, goodssl)
{
   constexpr auto testGoodAddresses = std::to_array(
      {
         /// https://badssl.com/dashboard/
         test_host_port{.host = "tls-v1-2.badssl.com", .port = 1012},
         test_host_port{.host = "sha256.badssl.com"},
         test_host_port{.host = "rsa2048.badssl.com"},
         test_host_port{.host = "ecc256.badssl.com"},
         test_host_port{.host = "ecc384.badssl.com"},

         /// https://browserleaks.com/tls
         test_host_port{.host = "tls12.browserleaks.com"},
         //test_host_port{.host = "tls13.browserleaks.com"},
      }
   );
   constexpr size_t testRecvBufferSize = 24 * 1024;
   constexpr size_t testSendBufferSize = 24 * 1024;
   auto const testThread = io_threads::tcp_client_thread
   {
      test_cpu_id,
      test_connections_capacity,
      testRecvBufferSize,
      testSendBufferSize
   };
   for (auto const &testGoodAddress : testGoodAddresses)
   {
      auto testIPv4Addresses = dns_resolver::resolve_ipv4(testGoodAddress.host, testGoodAddress.port);
      auto testTlsContext = tls_client_context{testGoodAddress.host, 0};
      auto testClient = test_tls_client{testThread, testTlsContext};
      testClient.expect_ready_to_send(std::format("GET / HTTP/1.1\r\nHost:{}\r\nAccept:*/*\r\n\r\n", testGoodAddress.host));
      testClient.expect_recv(
         [&testClient] (auto const *, auto const)
         {
            testClient.expect_disconnect();
         }
      );
      auto const testClientConfig =
         tcp_client_config{tcp_client_address{testIPv4Addresses.front()}}
         .with_keep_alive(
            tcp_keep_alive
            {
               .idleTimeout = test_keep_alive_delay,
               .probeTimeout = test_keep_alive_delay,
               .probesCount = 0
            }
         )
         .with_nodelay()
         .with_user_timeout(test_good_request_timeout * 5)
      ;
      testClient.expect_ready_to_connect(testClientConfig);
      ASSERT_EQ(std::future_status::ready, testClient.wait_for(test_good_request_timeout * 10)) << testGoodAddress.host;
   }
}

}
