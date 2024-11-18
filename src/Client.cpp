/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "Client.hpp"
#include <climits>
#include "Stm32NetX.hpp"

using namespace Stm32NetXHttpWebClient;


UINT Client::create(CHAR *client_name, NX_IP *ip_ptr, NX_PACKET_POOL *pool_ptr, ULONG window_size) {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->println("Stm32NetXHttpWebClient::Client::create()");

    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-web-http/chapter3.md#nx_web_http_client_create
    const auto ret = nx_web_http_client_create(this, client_name, ip_ptr, pool_ptr, window_size);

    if (ret != NX_SUCCESS) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf("Stm32NetXHttpWebClient::Client[%s]: nx_web_http_client_create() = 0x%02x\r\n",
                         getName(), ret);
    }

    // Clear all flags
    flags.clear(ULONG_MAX);
    flags.set(IS_CREATED);

    return ret;
}

UINT Client::create() {
    return create(getNameNonConst(), Stm32NetX::NX->getIpInstance(), Stm32NetX::NX->getPacketPool(), 8 * 1024);
}

UINT Client::del() {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->println("Stm32NetXHttpWebClient::Client::del()");

    if(!flags.get(IS_CREATED)) {
        return NX_SUCCESS;
    }

    // Clear all flags
    flags.clear(ULONG_MAX);

    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-web-http/chapter3.md#nx_web_http_client_delete
    const auto ret = nx_web_http_client_delete(this);

    if (ret != NX_SUCCESS) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf("Stm32NetXHttpWebClient::Client[%s]: nx_web_http_client_delete() = 0x%02x\r\n",
                         getName(), ret);
    }
    return ret;
}

UINT Client::getStart(NXD_ADDRESS *ip_address, UINT server_port, CHAR *resource, CHAR *host, CHAR *username,
                      CHAR *password, ULONG wait_option) {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->println("Stm32NetXHttpWebClient::Client::getStart()");

    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-web-http/chapter3.md#nx_web_http_client_get_start
    const auto ret = nx_web_http_client_get_start(this,
                                                  ip_address,
                                                  server_port,
                                                  resource,
                                                  host,
                                                  username,
                                                  password,
                                                  wait_option
    );

    if (ret != NX_SUCCESS) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf("Stm32NetXHttpWebClient::Client[%s]: nx_web_http_client_get_start() = 0x%02x\r\n",
                         getName(), ret);
    }
    return ret;
}

UINT Client::responseBodyGet(NX_PACKET **packet_ptr, ULONG wait_option) {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->println("Stm32NetXHttpWebClient::Client::responseBodyGet()");

    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-web-http/chapter3.md#nx_web_http_client_response_body_get
    const auto ret = nx_web_http_client_response_body_get(this, packet_ptr, wait_option);

    if (ret != NX_SUCCESS) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf("Stm32NetXHttpWebClient::Client[%s]: nx_web_http_client_response_body_get() = 0x%02x\r\n",
                         getName(), ret);
    }
    return ret;
}


UINT Client::connect(NXD_ADDRESS *server_ip, UINT server_port, ULONG wait_option) {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->println("Stm32NetXHttpWebClient::Client::connect()");

    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-web-http/chapter3.md#nx_web_http_client_connect
    const auto ret = nx_web_http_client_connect(this,
                                                server_ip,
                                                server_port,
                                                wait_option
    );

    if (ret != NX_SUCCESS) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf("Stm32NetXHttpWebClient::Client[%s]: nx_web_http_client_connect() = 0x%02x\r\n",
                         getName(), ret);
    }

    flags.set(IS_CONNECTED);

    return ret;
}

bool Client::isReadyForConnect() {
    return flags.isSet(IS_CREATED) && !flags.isSet(IS_CONNECTED) && Stm32NetX::NX->isIpSet();
}


#if defined(LIBSMART_STM32NETX_ENABLE_TLS) && defined(NX_WEB_HTTPS_ENABLE)
UINT Client::getSecureStart(NXD_ADDRESS *ip_address, UINT server_port, CHAR *resource, CHAR *host, CHAR *username,
                            CHAR *password,
                            UINT (*tls_setup)(NX_WEB_HTTP_CLIENT *client_ptr, NX_SECURE_TLS_SESSION *tls_session),
                            ULONG wait_option) {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->println("Stm32NetXHttpWebClient::Client::getSecureStart()");

    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-web-http/chapter3.md#nx_web_http_client_get_secure_start
    const auto ret = nx_web_http_client_get_secure_start(this,
                                                         ip_address,
                                                         server_port,
                                                         resource,
                                                         host,
                                                         username,
                                                         password,
                                                         tls_setup,
                                                         wait_option
    );

    if (ret != NX_SUCCESS) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf("Stm32NetXHttpWebClient::Client[%s]: nx_web_http_client_get_secure_start() = 0x%02x\r\n",
                         getName(), ret);
    }
    return ret;
}

UINT Client::getSecureStart(NXD_ADDRESS *ip_address, UINT server_port, CHAR *resource, CHAR *host, CHAR *username,
                            CHAR *password, ULONG wait_option) {
    return getSecureStart(ip_address, server_port, resource, host, username, password,
                          bounce<Client, decltype(&Client::tlsSetupCallback), &Client::tlsSetupCallback,
                              NX_SECURE_TLS_SESSION *>,
                          wait_option
    );
}

UINT Client::tlsSetupCallback(NX_SECURE_TLS_SESSION *tls_session) {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->println("Stm32NetXHttpWebClient::Client::tlsSetupCallback()");


    UINT ret;

    // Initialize TLS module
    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-secure-tls/chapter4.md#nx_secure_tls_initialize
    nx_secure_tls_initialize();


    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-secure-tls/chapter4.md#nx_secure_tls_metadata_size_calculate
    ULONG metadata_size;
    ret = nx_secure_tls_metadata_size_calculate(&nx_crypto_tls_ciphers, &metadata_size);
    if (ret != NX_SUCCESS) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf("nx_secure_tls_metadata_size_calculate() = 0x%02x\r\n",
                         ret);
        return ret;
    }

    if (metadata_size > sizeof(crypto_metadata)) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf("metadata_size = %lu  >  sizeof(crypto_metadata) = %lu\r\n", metadata_size, sizeof(crypto_metadata));
    }

    // Create a TLS session
    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-secure-tls/chapter4.md#nx_secure_tls_session_create
    ret = nx_secure_tls_session_create(tls_session, &nx_crypto_tls_ciphers,
                                       crypto_metadata, sizeof(crypto_metadata));
    if (ret != NX_SUCCESS) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf("TLS session create failed. nx_secure_tls_session_create() = 0x%02x\r\n",
                         ret);
        return ret;
    }


    // Allocate space for packet reassembly
    ret = nx_secure_tls_session_packet_buffer_set(tls_session, tls_packet_buffer,
                                                  sizeof(tls_packet_buffer));
    if (ret != NX_SUCCESS) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf(
                    "nx_secure_tls_session_packet_buffer_set() = 0x%02x\r\n",
                    ret);
        return ret;
    }


    // Need to allocate space for the certificate coming in from the broker
    memset(&remote_certificate, 0, sizeof(NX_SECURE_X509_CERT));

    // allocate space for the certificate coming in from the remote host
    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-secure-tls/chapter4.md#nx_secure_tls_remote_certificate_allocate
    ret = nx_secure_tls_remote_certificate_allocate(tls_session, &remote_certificate,
                                                    remote_cert_buffer, sizeof(remote_cert_buffer));
    if (ret != NX_SUCCESS) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf(
                    "TLS remote certificate allocations failed. nx_secure_tls_remote_certificate_allocate() = 0x%02x\r\n",
                    ret);
        return ret;
    }


    // Add a CA Certificate to our trusted store for verifying incoming server certificates
    // nx_secure_x509_certificate_initialize(&trusted_certificate, trusted_cert_der,
                                          // trusted_cert_der_len, NX_NULL, 0, NULL, 0,
                                          // NX_SECURE_X509_KEY_TYPE_NONE);
    // nx_secure_tls_trusted_certificate_add(tls_session, &trusted_certificate);

    // Need to allocate space for the certificate coming in from the remote host
    // nx_secure_tls_remote_certificate_allocate(tls_session, &remote_certificate,
                                              // remote_cert_buffer, sizeof(remote_cert_buffer));
    // nx_secure_tls_remote_certificate_allocate(tls_session, &remote_issuer,
                                              // remote_issuer_buffer, sizeof(remote_issuer_buffer));

    return NX_SUCCESS;
}
#endif
