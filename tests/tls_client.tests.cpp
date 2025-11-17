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
   void expect_error(error_code_matcher errorCodeMatcher)
   {
      executor().execute(
         [this, errorCodeMatcher = std::move(errorCodeMatcher)] ()
         {
            EXPECT_CALL(*this, io_disconnected(testing::_))
               .WillOnce(
                  [this, errorCodeMatcher = std::move(errorCodeMatcher)] (auto const errorCode)
                  {
                     super::io_disconnected(errorCode);
                     EXPECT_THAT(errorCode, errorCodeMatcher) << errorCode.value() << ": " << errorCode.message();
                     EXPECT_CALL(*this, io_data_decrypted(testing::_)).Times(0);
                     EXPECT_CALL(*this, io_data_to_encrypt(testing::_, testing::_)).Times(0);
                     EXPECT_CALL(*this, io_disconnected(testing::_)).Times(0);
                     EXPECT_CALL(*this, io_ready_to_connect()).Times(0);
                     if (nullptr != m_internalState)
                     {
                        m_connected.store(false, std::memory_order_relaxed);
                        m_internalState->done.set_value();
                     }
                     else
                     {
                        EXPECT_FALSE(m_connected.load(std::memory_order_relaxed));
                     }
                  }
               )
            ;
         }
      );
   }

   void expect_ready_to_connect(tcp_client_config testConfig)
   {
      m_internalState = std::make_unique<internal_state>();
      executor().execute(
         [this, testConfig = std::move(testConfig)] ()
         {
            EXPECT_CALL(*this, io_ready_to_connect()).WillOnce(testing::Return(std::move(testConfig)));
         }
      );
      ready_to_connect();
   }

   void expect_ready_to_connect_deferred(steady_time const testNotBeforeTime)
   {
      m_internalState = std::make_unique<internal_state>();
      ready_to_connect_deferred(testNotBeforeTime);
   }

   void expect_ready_to_connect_deferred(tcp_client_config testConfig, steady_time const testNotBeforeTime)
   {
      m_internalState = std::make_unique<internal_state>();
      executor().execute(
         [this, testConfig = std::move(testConfig)] ()
         {
            EXPECT_CALL(*this, io_ready_to_connect()).WillOnce(testing::Return(std::move(testConfig)));
         }
      );
      ready_to_connect_deferred(testNotBeforeTime);
   }

   void expect_ready_to_send(std::string message)
   {
      executor().execute(
         [this, message = std::move(message)] ()
         {
            EXPECT_CALL(*this, io_data_to_encrypt(testing::_, testing::_))
               .WillRepeatedly(
                  [this, message = std::move(message)] (auto const &dataChunk, auto &bytesWritten)
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
         }
      );
      ready_to_send();
   }

   void expect_ready_to_send(std::function<void()> sendHandler)
   {
      ASSERT_TRUE(sendHandler);
      executor().execute(
         [this, sendHandler = std::move(sendHandler)] ()
         {
            EXPECT_CALL(*this, io_data_to_encrypt(testing::_, testing::_))
               .WillOnce(
                  [sendHandler = std::move(sendHandler)] (auto const &, auto &bytesWritten)
                  {
                     sendHandler();
                     bytesWritten = 0;
                     return std::error_code{};
                  }
               )
            ;
         }
      );
      ready_to_send();
   }

   void expect_ready_to_send_deferred(steady_time const testNotBeforeTime)
   {
      ready_to_send_deferred(testNotBeforeTime);
   }

   void expect_ready_to_send_deferred(std::string message, steady_time const testNotBeforeTime)
   {
      executor().execute(
         [this, message = std::move(message)] ()
         {
            EXPECT_CALL(*this, io_data_to_encrypt(testing::_, testing::_))
               .WillRepeatedly(
                  [this, message = std::move(message)] (auto const &dataChunk, auto &bytesWritten)
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
         }
      );
      ready_to_send_deferred(testNotBeforeTime);
   }

   template<typename recv_handler>
   void expect_recv(recv_handler recvHandler)
   {
      executor().execute(
         [this, recvHandler = std::move(recvHandler)] ()
         {
            EXPECT_CALL(*this, io_data_decrypted(testing::_))
               .WillOnce(
                  [recvHandler = std::move(recvHandler)] (auto const &dataChunk)
                  {
                     recvHandler(dataChunk);
                     return std::error_code{};
                  }
               )
            ;
         }
      );
   }

   template<typename recv_handler>
   void expect_recv(std::string expectedMessage, recv_handler &&recvHandler)
   {
      executor().execute(
         [this, expectedMessage = std::move(expectedMessage), recvHandler = std::move(recvHandler)] ()
         {
            EXPECT_CALL(*this, io_data_decrypted(testing::_))
               .WillOnce(
                  [expectedMessage = std::move(expectedMessage), recvHandler = std::move(recvHandler)] (auto const &dataChunk)
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
      );
   }

   [[nodiscard]] auto wait_for(time_duration const timeout) const
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

   MOCK_METHOD(std::error_code, io_data_decrypted, (data_chunk const &), (final));
   MOCK_METHOD(std::error_code, io_data_to_encrypt, (data_chunk const &, size_t &), (final));
   MOCK_METHOD(void, io_disconnected, (std::error_code const &), (final));
   MOCK_METHOD(tcp_client_config, io_ready_to_connect, (), (final));
};

using test_tls_client = testing::StrictMock<tls_client_mock>;

using tls_client = testsuite;

}

TEST_F(tls_client, connect_timeout)
{
   constexpr uint32_t testSocketListCapacity{1,};
   constexpr uint32_t testRecvBufferSize{1,};
   constexpr uint32_t testSendBufferSize{1,};
   x509_store const testX509Store{x509_store_config{},};
   constexpr uint32_t testTlsSessionListCapacity{1,};
   tls_client_context const testTlsContext
   {
      tcp_client_thread{thread_config{}, testSocketListCapacity, testRecvBufferSize, testSendBufferSize,},
      testX509Store,
      test_domain,
      testTlsSessionListCapacity,
   };
   auto testClient = test_tls_client{testTlsContext,};
   constexpr uint16_t testPort{444,};
   test_tcp_connect_timeout(testClient, testPort);
}

TEST_F(tls_client, https)
{
   constexpr uint32_t testSocketListCapacity{1,};
   constexpr uint32_t testRecvBufferSize{2 * 1024,};
   constexpr uint32_t testSendBufferSize{2 * 1024,};
   tcp_client_thread const testThread{thread_config{}, testSocketListCapacity, testRecvBufferSize, testSendBufferSize,};
#if (defined(IO_THREADS_OPENSSL))
   x509_store const testX509Store{test_certificate_pem(), x509_format::pem,};
#elif (defined(IO_THREADS_SCHANNEL))
   x509_store const testX509Store{test_certificate_p12(), x509_format::p12,};
#endif
   constexpr uint32_t testTlsSessionListCapacity{1,};
   tls_client_context const testTlsContext{testThread, testX509Store, test_domain, testTlsSessionListCapacity,};
   auto testClient = test_tls_client{testTlsContext,};
   test_rest_client<test_tls_stream>(testThread, testClient);
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
#if (defined(IO_THREADS_OPENSSL))
   std::vector<std::error_code> const testExpiredErrorCodes{make_x509_error_code(X509_V_ERR_CERT_HAS_EXPIRED),};
   std::vector<std::error_code> const testWrongHostErrorCodes{make_x509_error_code(X509_V_ERR_HOSTNAME_MISMATCH),};
   std::vector<std::error_code> const testSelfSignedErrorCodes{make_x509_error_code(X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT),};
   std::vector<std::error_code> const testUntrustedRootErrorCodes{make_x509_error_code(X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN),};
   std::vector<std::error_code> const testSuperfishErrorCodes{make_x509_error_code(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY),};
   std::vector<std::error_code> const testEDellRootErrorCodes{make_x509_error_code(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY),};
   std::vector<std::error_code> const testDSDTestProviderErrorCodes{make_x509_error_code(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY),};
   std::vector<std::error_code> const testPreactCLIErrorCodes{make_x509_error_code(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY),};
   std::vector<std::error_code> const testWebpackDevServerErrorCodes{make_x509_error_code(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY),};
   std::vector<std::error_code> const testRC4ErrorCodes{make_tls_error_code(ERR_PACK(ERR_LIB_SSL, 0, SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE)),};
   std::vector<std::error_code> const testRC4MD5ErrorCodes{make_tls_error_code(ERR_PACK(ERR_LIB_SSL, 0, SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE)),};
   std::vector<std::error_code> const testDH480ErrorCodes{make_tls_error_code(ERR_PACK(ERR_LIB_SSL, 0, SSL_R_BAD_DH_VALUE)),};
   std::vector<std::error_code> const testDH512ErrorCodes{make_tls_error_code(ERR_PACK(ERR_LIB_SSL, 0, SSL_R_DH_KEY_TOO_SMALL)),};
   std::vector<std::error_code> const testDH1024ErrorCodes{make_tls_error_code(ERR_PACK(ERR_LIB_SSL, 0, SSL_R_DH_KEY_TOO_SMALL)),};
   std::vector<std::error_code> const testNullErrorCodes{make_tls_error_code(ERR_PACK(ERR_LIB_SSL, 0, SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE)),};
   std::vector<std::error_code> const testTLSv1_0ErrorCodes{make_tls_error_code(ERR_PACK(ERR_LIB_SSL, 0, SSL_R_UNSUPPORTED_PROTOCOL)),};
   std::vector<std::error_code> const testTLSv1_1ErrorCodes{make_tls_error_code(ERR_PACK(ERR_LIB_SSL, 0, SSL_R_UNSUPPORTED_PROTOCOL)),};
   std::vector<std::error_code> const test3DESErrorCodes{make_tls_error_code(ERR_PACK(ERR_LIB_SSL, 0, SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE)),};
   std::vector<std::error_code> const testRevokedErrorCodes{make_x509_error_code(X509_V_ERR_CERT_REVOKED),};
   std::vector<std::error_code> const testCurveBallErrorCodes{make_x509_error_code(X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN),};
   std::vector<std::error_code> const testLogjamErrorCodes{make_tls_error_code(ERR_PACK(ERR_LIB_SSL, 0, SSL_R_DH_KEY_TOO_SMALL)),};
   std::vector<std::error_code> const testFREAKErrorCodes{make_tls_error_code(ERR_PACK(ERR_LIB_SSL, 0, SSL_R_UNSUPPORTED_PROTOCOL)),};
#elif (defined(IO_THREADS_SCHANNEL))
   std::vector<std::error_code> const testExpiredErrorCodes{make_x509_error_code(SEC_E_CERT_EXPIRED),};
   std::vector<std::error_code> const testWrongHostErrorCodes{make_x509_error_code(SEC_E_WRONG_PRINCIPAL),};
   std::vector<std::error_code> const testSelfSignedErrorCodes{make_x509_error_code(SEC_E_UNTRUSTED_ROOT),};
   std::vector<std::error_code> const testUntrustedRootErrorCodes{make_x509_error_code(SEC_E_UNTRUSTED_ROOT),};
   std::vector<std::error_code> const testSuperfishErrorCodes{make_x509_error_code(SEC_E_UNTRUSTED_ROOT),};
   std::vector<std::error_code> const testEDellRootErrorCodes{make_x509_error_code(SEC_E_UNTRUSTED_ROOT),};
   std::vector<std::error_code> const testDSDTestProviderErrorCodes{make_x509_error_code(SEC_E_UNTRUSTED_ROOT),};
   std::vector<std::error_code> const testPreactCLIErrorCodes{make_x509_error_code(SEC_E_UNTRUSTED_ROOT),};
   std::vector<std::error_code> const testWebpackDevServerErrorCodes
   {
      make_x509_error_code(TRUST_E_CERT_SIGNATURE),
      make_x509_error_code(SEC_E_UNTRUSTED_ROOT),
   };
   std::vector<std::error_code> const testRC4ErrorCodes{make_tls_error_code(SEC_E_ILLEGAL_MESSAGE),};
   std::vector<std::error_code> const testRC4MD5ErrorCodes{make_tls_error_code(SEC_E_ILLEGAL_MESSAGE),};
   std::vector<std::error_code> const testDH480ErrorCodes
   {
      make_tls_error_code(SEC_E_ILLEGAL_MESSAGE),
      make_tls_error_code(SEC_E_INVALID_PARAMETER),
   };
   std::vector<std::error_code> const testDH512ErrorCodes
   {
      make_tls_error_code(SEC_E_ILLEGAL_MESSAGE),
      make_tls_error_code(SEC_E_INVALID_PARAMETER),
   };
   std::vector<std::error_code> const testDH1024ErrorCodes{make_tls_error_code(SEC_E_ILLEGAL_MESSAGE),};
   std::vector<std::error_code> const testNullErrorCodes{make_tls_error_code(SEC_E_ILLEGAL_MESSAGE),};
   std::vector<std::error_code> const testTLSv1_0ErrorCodes
   {
      make_tls_error_code(SEC_E_ILLEGAL_MESSAGE),
      make_x509_error_code(SEC_E_ALGORITHM_MISMATCH),
   };
   std::vector<std::error_code> const testTLSv1_1ErrorCodes
   {
      make_tls_error_code(SEC_E_ILLEGAL_MESSAGE),
      make_x509_error_code(SEC_E_ALGORITHM_MISMATCH),
   };
   std::vector<std::error_code> const test3DESErrorCodes{make_tls_error_code(SEC_E_ILLEGAL_MESSAGE),};
   std::vector<std::error_code> const testDH2048ErrorCodes{make_tls_error_code(SEC_E_ILLEGAL_MESSAGE),};
   std::vector<std::error_code> const testRevokedErrorCodes{make_x509_error_code(CRYPT_E_REVOKED),};
   std::vector<std::error_code> const testCurveBallErrorCodes{make_x509_error_code(SEC_E_UNTRUSTED_ROOT),};
   std::vector<std::error_code> const testLogjamErrorCodes
   {
      make_tls_error_code(SEC_E_ILLEGAL_MESSAGE),
      make_tls_error_code(SEC_E_INVALID_PARAMETER),
   };
   std::vector<std::error_code> const testFREAKErrorCodes
   {
      make_tls_error_code(SEC_E_ILLEGAL_MESSAGE),
      make_x509_error_code(SEC_E_ALGORITHM_MISMATCH),
   };
#endif
   auto const testBadAddresses
   {
      std::to_array(
         {
         /// https://badssl.com/dashboard/
         ///   Certificate Validation (High Risk)
               test_host_port_error_code{.host = "expired.badssl.com", .errorCodes = testExpiredErrorCodes,},
               test_host_port_error_code{.host = "wrong.host.badssl.com", .errorCodes = testWrongHostErrorCodes,},
               test_host_port_error_code{.host = "self-signed.badssl.com", .errorCodes = testSelfSignedErrorCodes,},
               test_host_port_error_code{.host = "untrusted-root.badssl.com", .errorCodes = testUntrustedRootErrorCodes,},
         ///   Interception Certificates (High Risk)
               test_host_port_error_code{.host = "superfish.badssl.com", .errorCodes = testSuperfishErrorCodes,},
               test_host_port_error_code{.host = "edellroot.badssl.com", .errorCodes = testEDellRootErrorCodes,},
               test_host_port_error_code{.host = "dsdtestprovider.badssl.com", .errorCodes = testDSDTestProviderErrorCodes,},
               test_host_port_error_code{.host = "preact-cli.badssl.com", .errorCodes = testPreactCLIErrorCodes,},
               test_host_port_error_code{.host = "webpack-dev-server.badssl.com", .errorCodes = testWebpackDevServerErrorCodes,},
         ///   Broken Cryptography (Medium Risk)
               test_host_port_error_code{.host = "rc4.badssl.com", .errorCodes = testRC4ErrorCodes,},
               test_host_port_error_code{.host = "rc4-md5.badssl.com", .errorCodes = testRC4MD5ErrorCodes,},
               test_host_port_error_code{.host = "dh480.badssl.com", .errorCodes = testDH480ErrorCodes,},
               test_host_port_error_code{.host = "dh512.badssl.com", .errorCodes = testDH512ErrorCodes,},
#if (not defined(IO_THREADS_DH1024_ALLOWED)) ///< Skip test of DH-1024 deprecation
               test_host_port_error_code{.host = "dh1024.badssl.com", .errorCodes = testDH1024ErrorCodes,},
#endif
               test_host_port_error_code{.host = "null.badssl.com", .errorCodes = testNullErrorCodes,},
         ///   Legacy Cryptography (Moderate Risk)
               test_host_port_error_code{.host = "tls-v1-0.badssl.com", .port = 1010, .errorCodes = testTLSv1_0ErrorCodes,},
               test_host_port_error_code{.host = "tls-v1-1.badssl.com", .port = 1011, .errorCodes = testTLSv1_1ErrorCodes,},
#if (not defined(IO_THREADS_CBC_ALLOWED)) ///< Skip test of CBC ciphers deprecation
               test_host_port_error_code{.host = "cbc.badssl.com", .errorCodes = testCBCErrorCodes,},
#endif
#if (not defined(IO_THREADS_3DES_ALLOWED)) ///< Skip test of 3DES cipher deprecation
               test_host_port_error_code{.host = "3des.badssl.com", .errorCodes = test3DESErrorCodes,},
#endif
#if (not defined(IO_THREADS_DH2048_ALLOWED)) ///< Skip test of DH-2048 deprecation
               test_host_port_error_code{.host = "dh2048.badssl.com", .errorCodes = testDH2048ErrorCodes,},
#endif
         ///   Domain Security Policies
               test_host_port_error_code{.host = "revoked.badssl.com", .errorCodes = testRevokedErrorCodes,},

         /// https://clienttest.ssllabs.com:8443/ssltest/viewMyClient.html
         ///   CVE-2020-0601 (CurveBall) Vulnerability
               test_host_port_error_code{.host = "www.ssllabs.com", .port = 10446, .errorCodes = testCurveBallErrorCodes,},
         ///   Logjam Vulnerability
               test_host_port_error_code{.host = "www.ssllabs.com", .port = 10445, .errorCodes = testLogjamErrorCodes,},
         ///   FREAK Vulnerability
               test_host_port_error_code{.host = "www.ssllabs.com", .port = 10444, .errorCodes = testFREAKErrorCodes,},
         }
      ),
   };
   constexpr uint32_t testSocketListCapacity{1,};
   constexpr uint32_t testRecvBufferSize{tls_packet_size_limit,};
   constexpr uint32_t testSendBufferSize{2 * 1024,};
   tcp_client_thread const testThread{thread_config{}, testSocketListCapacity, testRecvBufferSize, testSendBufferSize,};
   std::vector<domain_address> testDomains;
   testDomains.reserve(testBadAddresses.size());
   for (auto const &testBadAddress : testBadAddresses)
   {
      testDomains.push_back(domain_address{.hostname = std::string{testBadAddress.host,}, .port = testBadAddress.port,});
   }
   x509_store const testX509Store{x509_store_config{}, testDomains,};
   constexpr uint32_t testTlsSessionListCapacity{1,};
   constexpr std::chrono::seconds testTimeout{1,};
   constexpr tcp_keep_alive testTcpKeepAlive{.idleTimeout = testTimeout, .probeTimeout = testTimeout, .probesCount = 0,};
   for (auto const &testBadAddress : testBadAddresses)
   {
      auto testIPv4Addresses{dns_resolver::resolve_ipv4(testBadAddress.host, testBadAddress.port),};
      ASSERT_FALSE(testIPv4Addresses.empty());
      tls_client_context const testTlsContext{testThread, testX509Store, testBadAddress.host, testTlsSessionListCapacity,};
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
      ASSERT_EQ(std::future_status::ready, testClient.wait_for(testTimeout)) << testBadAddress.host;
   }
}

#if (defined(IO_THREADS_SCHANNEL))
namespace
{

struct test_host_port final
{
   std::string_view host{"",};
   uint16_t port{443,};
   bool tls1_3Required{false,};
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
            test_host_port{.host = "mozilla-modern.badssl.com"},

         /// https://browserleaks.com/tls
            test_host_port{.host = "tls12.browserleaks.com"},
            test_host_port{.host = "tls13.browserleaks.com", .tls1_3Required = true},
         }
      ),
   };
   constexpr uint32_t testSocketListCapacity{1,};
   constexpr uint32_t testRecvBufferSize{tls_packet_size_limit,};
   constexpr uint32_t testSendBufferSize{2 * 1024,};
   tcp_client_thread const testThread{thread_config{}, testSocketListCapacity, testRecvBufferSize, testSendBufferSize,};
   std::vector<domain_address> testDomains;
   testDomains.reserve(testGoodAddresses.size());
   for (auto const &testGoodAddress : testGoodAddresses)
   {
      if ((true == testGoodAddress.tls1_3Required) && (false == tls1_3_available()))
      {
         continue;
      }
      testDomains.push_back(domain_address{.hostname = std::string{testGoodAddress.host,}, .port = testGoodAddress.port,});
   }
   x509_store const testX509Store{x509_store_config{}, testDomains,};
   constexpr uint32_t testTlsSessionListCapacity{1,};
   constexpr std::chrono::seconds testTimeout{1,};
   constexpr tcp_keep_alive testTcpKeepAlive{.idleTimeout = testTimeout, .probeTimeout = testTimeout, .probesCount = 0,};
   for (auto const &testGoodAddress : testGoodAddresses)
   {
      if ((true == testGoodAddress.tls1_3Required) && (false == tls1_3_available()))
      {
         continue;
      }
      auto const testIPv4Addresses{dns_resolver::resolve_ipv4(testGoodAddress.host, testGoodAddress.port),};
      tls_client_context const testTlsContext{testThread, testX509Store, testGoodAddress.host, testTlsSessionListCapacity,};
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
      ASSERT_EQ(std::future_status::ready, testClient.wait_for(testTimeout)) << testGoodAddress.host;
   }
}
#endif

}
