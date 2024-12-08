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

#include "tcp/test_ssl_certificate.hpp"
#include "tcp/test_tcp_connect_timeout.hpp"
#include "tcp/test_tcp_server_context.hpp"
#include "tcp/rest/test_rest_client.hpp"
#include "testsuite.hpp"

#include <io_threads/dns_resolver.hpp>
#include <io_threads/tls_client.hpp>

namespace io_threads::tests
{

namespace
{

class tls_client_mock : public io_threads::tls_client
{
private:
   using super = io_threads::tls_client;

   struct internal_state final
   {
      std::promise<void> done{};
      std::future<void> doneFuture{done.get_future(),};
   };

public:
   using super::super;

   tls_client_mock &operator = (tls_client_mock &&) = delete;
   tls_client_mock &operator = (tls_client_mock const &) = delete;

   void expect_disconnect()
   {
      expect_error(std::error_code{});
      ready_to_disconnect();
   }

   template<typename error_code_matcher>
   void expect_error(error_code_matcher &&errorCodeMatcher)
   {
      EXPECT_CALL(*this, io_disconnected(testing::_))
         .WillOnce(
            [this, errorCodeMatcher] (auto const errorCode)
            {
               m_connected.store(false, std::memory_order_relaxed);
               super::io_disconnected(errorCode);
               EXPECT_THAT(errorCode, errorCodeMatcher) << errorCode.value() << ": " << errorCode.message();
               EXPECT_CALL(*this, io_data_decrypted(testing::_)).Times(0);
               EXPECT_CALL(*this, io_data_to_encrypt(testing::_, testing::_)).Times(0);
               EXPECT_CALL(*this, io_disconnected(testing::_)).Times(0);
               EXPECT_CALL(*this, io_ready_to_connect()).Times(0);
               assert(nullptr != m_internalState);
               m_internalState->done.set_value();
            }
         )
      ;
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
         .WillRepeatedly(
            [this, message] (auto const &dataChunk, auto &bytesWritten)
            {
               EXPECT_CALL(*this, io_data_to_encrypt(testing::_, testing::_)).WillRepeatedly(
                  [this] (auto const &, auto &bytesWritten)
                  {
                     bytesWritten = 0;
                     EXPECT_CALL(*this, io_data_to_encrypt(testing::_, testing::_)).Times(0);
                     return std::error_code{};
                  }
               );
               assert(message.size() <= dataChunk.bytesLength);
               std::memcpy(dataChunk.bytes, message.data(), message.size());
               bytesWritten = message.size();
               return std::error_code{};
            }
         )
      ;
      if (true == m_connected.load(std::memory_order_relaxed))
      {
         ready_to_send();
      }
   }

   template<typename recv_handler>
   void expect_recv(recv_handler &&recvHandler)
   {
      EXPECT_CALL(*this, io_data_decrypted(testing::_))
         .WillOnce(
            [recvHandler] (auto const &dataChunk)
            {
               recvHandler(dataChunk);
               return std::error_code{};
            }
         )
      ;
   }

   template<typename recv_handler>
   void expect_recv(std::string const &expectedMessage, recv_handler &&recvHandler)
   {
      EXPECT_CALL(*this, io_data_decrypted(testing::_))
         .WillOnce(
            [expectedMessage, recvHandler] (auto const &dataChunk)
            {
               std::string_view const receivedMessage
               {
                  std::bit_cast<char const *>(dataChunk.bytes),
                  dataChunk.bytesLength,
               };
               EXPECT_EQ(expectedMessage, receivedMessage);
               recvHandler();
               return std::error_code{};
            }
         )
      ;
   }

   [[nodiscard]] auto wait_for(std::chrono::seconds const timeout) const
   {
      assert(nullptr != m_internalState);
      return m_internalState->doneFuture.wait_for(timeout);
   }

private:
   std::unique_ptr<internal_state> m_internalState{nullptr,};
   std::atomic_bool m_connected{false,};

   void io_connected() final
   {
      super::io_connected();
      m_connected.store(true, std::memory_order_relaxed);
   }

   MOCK_METHOD(std::error_code, io_data_decrypted, (data_chunk), (final));
   MOCK_METHOD(std::error_code, io_data_to_encrypt, (data_chunk, size_t &), (final));
   MOCK_METHOD(void, io_disconnected, (std::error_code), (final));
   MOCK_METHOD(tcp_client_config, io_ready_to_connect, (), (final));
};

using test_tls_client = testing::StrictMock<tls_client_mock>;

using tls_client = testsuite;

}

TEST_F(tls_client, connect_timeout)
{
   constexpr uint16_t testCpuId{0,};
   constexpr size_t testCapacityOfSocketDescriptorList{0,};
   constexpr size_t testCapacityOfInputOutputBuffer{1,};
   tcp_client_thread const testThread
   {
      testCpuId,
      testCapacityOfSocketDescriptorList,
      testCapacityOfInputOutputBuffer,
   };
   constexpr size_t testTlsSessionsCapacity{0,};
   auto testTlsContext = tls_client_context{testThread, test_domain, testTlsSessionsCapacity,};
   auto testClient = test_tls_client{testTlsContext,};
   constexpr uint16_t testPort{444,};
   test_tcp_connect_timeout(testClient, testPort);
}

TEST_F(tls_client, https)
{
   constexpr uint16_t testCpuId{0,};
   constexpr size_t testCapacityOfSocketDescriptorList{0,};
   constexpr size_t testCapacityOfInputOutputBuffer{4 * 1024,};
   tcp_client_thread const testThread
   {
      testCpuId,
      testCapacityOfSocketDescriptorList,
      testCapacityOfInputOutputBuffer,
   };
   constexpr size_t testTlsSessionsCapacity{1,};
   tls_client_context const testTlsContext
   {
      testThread,
      test_domain,
      ssl_certificate{test_certificate_p12(), ssl_certificate_type::p12,},
      testTlsSessionsCapacity,
   };
   auto testClient = test_tls_client{testTlsContext,};
   test_rest_client<test_tls_stream>(testClient);
}

namespace
{

struct test_host_port_error_code final
{
   std::string_view host{"",};
   uint16_t port{443,};
   std::vector<std::error_code> const &errorCodes;
};

}

TEST_F(tls_client, badssl)
{
#if (defined(__linux__))
   std::vector<std::error_code> const testCertificateExpiredErrorCodes{};
   std::vector<std::error_code> const testWrongHostErrorCodes{};
   std::vector<std::error_code> const testUntrustedRootErrorCodes{};
   std::vector<std::error_code> const testIllegalMessageErrorCodes{};
   std::vector<std::error_code> const testAlgorithmMismatchErrorCodes{};
   std::vector<std::error_code> const testCertificateRevokedErrorCodes{};
#elif (defined(_WIN32) || defined(_WIN64))
   std::vector<std::error_code> const testCertificateExpiredErrorCodes{std::error_code{SEC_E_CERT_EXPIRED, std::system_category(),},};
   std::vector<std::error_code> const testWrongHostErrorCodes{std::error_code{SEC_E_WRONG_PRINCIPAL, std::system_category(),},};
   std::vector<std::error_code> const testUntrustedRootErrorCodes{std::error_code{SEC_E_UNTRUSTED_ROOT, std::system_category(),},};
   std::vector<std::error_code> const testIllegalMessageErrorCodes
   {
      std::error_code{SEC_E_ILLEGAL_MESSAGE, std::system_category(),},
      std::error_code{SEC_E_INVALID_PARAMETER, std::system_category(),},
   };
   std::vector<std::error_code> const testAlgorithmMismatchErrorCodes
   {
      std::error_code{SEC_E_ILLEGAL_MESSAGE, std::system_category(),},
      std::error_code{SEC_E_ALGORITHM_MISMATCH, std::system_category(),},
   };
   std::vector<std::error_code> const testCertificateRevokedErrorCodes{std::error_code{CRYPT_E_REVOKED, std::system_category(),},};
#endif
   auto const testBadAddresses
   {
      std::to_array(
         {
            /// https://badssl.com/dashboard/
            ///   Certificate Validation (High Risk)
                  test_host_port_error_code{.host = "expired.badssl.com", .errorCodes = testCertificateExpiredErrorCodes,},
                  test_host_port_error_code{.host = "wrong.host.badssl.com", .errorCodes = testWrongHostErrorCodes,},
                  test_host_port_error_code{.host = "self-signed.badssl.com", .errorCodes = testUntrustedRootErrorCodes,},
                  test_host_port_error_code{.host = "untrusted-root.badssl.com", .errorCodes = testUntrustedRootErrorCodes,},
            ///   Interception Certificates (High Risk)
                  test_host_port_error_code{.host = "superfish.badssl.com", .errorCodes = testUntrustedRootErrorCodes,},
                  test_host_port_error_code{.host = "edellroot.badssl.com", .errorCodes = testUntrustedRootErrorCodes,},
                  test_host_port_error_code{.host = "dsdtestprovider.badssl.com", .errorCodes = testUntrustedRootErrorCodes,},
                  test_host_port_error_code{.host = "preact-cli.badssl.com", .errorCodes = testUntrustedRootErrorCodes,},
                  test_host_port_error_code{.host = "webpack-dev-server.badssl.com", .errorCodes = testUntrustedRootErrorCodes,},
            ///   Broken Cryptography (Medium Risk)
                  test_host_port_error_code{.host = "rc4.badssl.com", .errorCodes = testIllegalMessageErrorCodes,},
                  test_host_port_error_code{.host = "rc4-md5.badssl.com", .errorCodes = testIllegalMessageErrorCodes,},
                  test_host_port_error_code{.host = "dh480.badssl.com", .errorCodes = testIllegalMessageErrorCodes,},
                  test_host_port_error_code{.host = "dh512.badssl.com", .errorCodes = testIllegalMessageErrorCodes,},
#if (not defined(IO_THREADS_DH1024_ALLOWED)) ///< Skip test of DH-1024 deprecation
                  test_host_port_error_code{.host = "dh1024.badssl.com", .errorCodes = testIllegalMessageErrorCodes,},
#endif
                  test_host_port_error_code{.host = "null.badssl.com", .errorCodes = testIllegalMessageErrorCodes,},
            ///   Legacy Cryptography (Moderate Risk)
                  test_host_port_error_code{.host = "tls-v1-0.badssl.com", .port = 1010, .errorCodes = testAlgorithmMismatchErrorCodes,},
                  test_host_port_error_code{.host = "tls-v1-1.badssl.com", .port = 1011, .errorCodes = testAlgorithmMismatchErrorCodes,},
#if (not defined(IO_THREADS_CBC_ALLOWED)) ///< Skip test of CBC ciphers deprecation
                  test_host_port_error_code{.host = "cbc.badssl.com", .errorCodes = testAlgorithmMismatchErrorCodes,},
#endif
#if (not defined(IO_THREADS_3DES_ALLOWED)) ///< Skip test of 3DES cipher deprecation
                  test_host_port_error_code{.host = "3des.badssl.com", .errorCodes = testIllegalMessageErrorCodes,},
#endif
#if (not defined(IO_THREADS_DH2048_ALLOWED)) ///< Skip test of DH-2048 deprecation
                  test_host_port_error_code{.host = "dh2048.badssl.com", .errorCodes = testIllegalMessageErrorCodes,},
#endif
            ///   Domain Security Policies
                  test_host_port_error_code{.host = "revoked.badssl.com", .errorCodes = testCertificateRevokedErrorCodes,},

            /// https://clienttest.ssllabs.com:8443/ssltest/viewMyClient.html
            ///   CVE-2020-0601 (CurveBall) Vulnerability
                  test_host_port_error_code{.host = "www.ssllabs.com", .port = 10446, .errorCodes = testUntrustedRootErrorCodes,},
            ///   Logjam Vulnerability
                  test_host_port_error_code{.host = "www.ssllabs.com", .port = 10445, .errorCodes = testIllegalMessageErrorCodes,},
            ///   FREAK Vulnerability
                  test_host_port_error_code{.host = "www.ssllabs.com", .port = 10444, .errorCodes = testAlgorithmMismatchErrorCodes,},
         }
      ),
   };
   constexpr uint16_t testCpuId{0,};
   constexpr size_t testCapacityOfSocketDescriptorList{1,};
   constexpr size_t testCapacityOfInputOutputBuffer{tls_packet_size_limit,};
   tcp_client_thread const testThread
   {
      testCpuId,
      testCapacityOfSocketDescriptorList,
      testCapacityOfInputOutputBuffer,
   };
   constexpr size_t testTlsSessionsCapacity{0,};
   constexpr std::chrono::seconds testTimeout{5,};
   constexpr tcp_keep_alive testTcpKeepAlive
   {
      .idleTimeout = testTimeout,
      .probeTimeout = testTimeout,
      .probesCount = 0,
   };
   for (auto const &testBadAddress : testBadAddresses)
   {
      auto testIPv4Addresses{dns_resolver::resolve_ipv4(testBadAddress.host, testBadAddress.port),};
      ASSERT_FALSE(testIPv4Addresses.empty());
      tls_client_context const testTlsContext{testThread, testBadAddress.host, testTlsSessionsCapacity,};
      test_tls_client testClient{testTlsContext,};
      testClient.expect_error(testing::AnyOfArray(testBadAddress.errorCodes));
      testClient.expect_ready_to_send(std::format("GET / HTTP/1.1\r\nHost:{}\r\nAccept:*/*\r\n\r\n", testBadAddress.host));
      auto const testClientConfig
      {
         tcp_client_config{tcp_client_address{testIPv4Addresses.front(),},}
            .with_keep_alive(testTcpKeepAlive)
            .with_nodelay()
            .with_user_timeout(testTimeout)
      };
      testClient.expect_ready_to_connect(testClientConfig);
      ASSERT_EQ(std::future_status::ready, testClient.wait_for(testTimeout * 2)) << testBadAddress.host;
   }
}

namespace
{

struct test_host_port final
{
   std::string_view host{"",};
   uint16_t port{443,};
};

}

TEST_F(tls_client, goodssl)
{
   constexpr auto testGoodAddresses
   {
      std::to_array(
         {
            /// https://badssl.com/dashboard/
               test_host_port{.host = "tls-v1-2.badssl.com", .port = 1012},
               test_host_port{.host = "sha256.badssl.com"},
               test_host_port{.host = "rsa2048.badssl.com"},
               test_host_port{.host = "ecc256.badssl.com"},
               test_host_port{.host = "ecc384.badssl.com"},
#if (not defined(_WIN32) && not defined(_WIN64))
               test_host_port{.host = "extended-validation.badssl.com"},
#endif
               test_host_port{.host = "mozilla-modern.badssl.com"},

            /// https://browserleaks.com/tls
               test_host_port{.host = "tls12.browserleaks.com"},
#if (defined(IO_THREADS_TLSv1_3_AVAILABLE))
               test_host_port{.host = "tls13.browserleaks.com"},
#endif
         }
      ),
   };
   constexpr uint16_t testCpuId{0,};
   constexpr size_t testCapacityOfSocketDescriptorList{1,};
   constexpr size_t testCapacityOfInputOutputBuffer{tls_packet_size_limit,};
   tcp_client_thread const testThread
   {
      testCpuId,
      testCapacityOfSocketDescriptorList,
      testCapacityOfInputOutputBuffer,
   };
   constexpr size_t testTlsSessionsCapacity{1,};
   constexpr std::chrono::seconds testTimeout{5,};
   constexpr tcp_keep_alive testTcpKeepAlive
   {
      .idleTimeout = testTimeout,
      .probeTimeout = testTimeout,
      .probesCount = 0,
   };
   for (auto const &testGoodAddress : testGoodAddresses)
   {
      auto const testIPv4Addresses{dns_resolver::resolve_ipv4(testGoodAddress.host, testGoodAddress.port),};
      tls_client_context const testTlsContext{testThread, testGoodAddress.host, testTlsSessionsCapacity,};
      test_tls_client testClient{testTlsContext,};
      testClient.expect_recv(
         [&testClient] (auto const)
         {
            testClient.expect_disconnect();
         }
      );
      testClient.expect_ready_to_send(std::format("GET / HTTP/1.1\r\nHost:{}\r\nAccept:*/*\r\n\r\n", testGoodAddress.host));
      auto const testClientConfig
      {
         tcp_client_config{tcp_client_address{testIPv4Addresses.front(),},}
            .with_keep_alive(testTcpKeepAlive)
            .with_nodelay()
            .with_user_timeout(testTimeout)
         ,
      };
      testClient.expect_ready_to_connect(testClientConfig);
      ASSERT_EQ(std::future_status::ready, testClient.wait_for(testTimeout * 2)) << testGoodAddress.host;
   }
}

}
