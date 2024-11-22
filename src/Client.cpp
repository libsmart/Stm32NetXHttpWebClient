/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "Client.hpp"
#include <climits>

#include "Address.hpp"
#include "Stm32NetX.hpp"

using namespace Stm32NetXHttpWebClient;

UINT Client::create() {
    return BaseClient::create(getNameNonConst(), Stm32NetX::NX->getIpInstance(), Stm32NetX::NX->getPacketPool(),
                              8 * 1024);
}

UINT Client::headerAdd(const char *field_name, const char *field_value) {
    return request_header_add(const_cast<char *>(field_name), strlen(field_name),
                              const_cast<char *>(field_value), strlen(field_value),
                              getTimeout());
}

UINT Client::initialize(HTTP_METHOD method, const CHAR *resource, const CHAR *host, const UINT input_size,
                        const CHAR *username, const CHAR *password) {
    return request_initialize_extended(method, const_cast<CHAR *>(resource), strlen(resource),
                                       const_cast<CHAR *>(host), strlen(host), input_size, 0,
                                       const_cast<CHAR *>(username), username == nullptr ? 0 : strlen(username),
                                       const_cast<CHAR *>(password), password == nullptr ? 0 : strlen(password),
                                       getTimeout());
}

UINT Client::initialize(HTTP_METHOD method, const CHAR *resource, const CHAR *host, const UINT input_size) {
    return initialize(method, resource, host, input_size, nullptr, nullptr);
}

UINT Client::initialize(HTTP_METHOD method, const CHAR *resource, const CHAR *host) {
    return initialize(method, resource, host, 0);
}

UINT Client::packetSend(Stm32NetX::Packet *packet) {
    const auto ret = request_packet_send(static_cast<NX_PACKET *>(*packet), 0, getTimeout());
    if (ret == NX_SUCCESS) {
        packet->forget();
    }
    return ret;
}

UINT Client::send() {
    return request_send(getTimeout());
}

UINT Client::connect(const Stm32NetX::Uri &uri) {
    Stm32NetX::Address peerIpAddress{getLogger()};

    UINT peerPort = uri.get_port();
    if (peerPort == 0) {
        // No port specified => use default
        if (uri.get_scheme() == "http") {
            peerPort = LIBSMART_STM32NETXHTTPWEBCLIENT_HTTP_PORT;
        }
        if (uri.get_scheme() == "https") {
            peerPort = LIBSMART_STM32NETXHTTPWEBCLIENT_HTTPS_PORT;
        }
    }


    peerIpAddress = uri.get_host().c_str();
    if (!peerIpAddress.isValid()) {
        // IP not valid => try dns
        Stm32NetX::Dns *dns = Stm32NetX::NX->getDns();
        volatile auto const ret = dns->hostByNameGet(const_cast<CHAR *>(uri.get_host().c_str()), &peerIpAddress,
                                                     getTimeout(), NX_IP_VERSION_V4);
    }

    return BaseClient::connect(&peerIpAddress, peerPort, getTimeout());
}

void Client::initializeRequest(Stm32NetXHttp::Methods method, const Stm32NetX::Uri &uri, UINT input_size) {
    log()->printf("Stm32NetXHttpWebClient::Client::initializeRequest()\r\n");
    log()->printf("method: 0x%02x\r\n", std::visit([](auto &arg) -> auto { return (UINT) arg; }, method));
    log()->printf("method: %s\r\n", std::visit([](auto &arg) -> auto { return (const char *) arg; }, method));
    log()->printf("uri: %s\r\n", uri.to_string().c_str());
    log()->printf("scheme: %s\r\n", uri.get_scheme().c_str());
    log()->printf("host: %s\r\n", uri.get_host().c_str());


    auto ret = initialize(
        std::visit([](auto &arg) -> auto { return static_cast<HTTP_METHOD>(arg); }, method),
        uri.get_path().c_str(),
        uri.get_host().c_str(),
        input_size,
        uri.get_username().empty() ? nullptr : uri.get_username().c_str(),
        uri.get_username().empty() ? nullptr : uri.get_username().c_str()
    );
}

void Client::requestStart(Stm32NetXHttp::Methods method, const Stm32NetX::Uri &uri) {
    requestStart(method, uri, 0);
}

void Client::requestStart(Stm32NetXHttp::Methods method, const Stm32NetX::Uri &uri, UINT input_size) {
    create();
    connect(uri);
    initializeRequest(method, uri, input_size);
}

UINT Client::packetAllocate(NX_PACKET **packet_ptr) {
    return request_packet_allocate(packet_ptr, getTimeout());
}

UINT Client::packetAllocate(Stm32NetX::Packet &packet) {
    NX_PACKET *packet_ptr;
    const auto ret = request_packet_allocate(&packet_ptr, getTimeout());
    packet = packet_ptr;
    return ret;
}


UINT Client::responseBodyGet(NX_PACKET **packet_ptr, ULONG wait_option) {
    return response_body_get(packet_ptr, wait_option);
}

UINT Client::responseBodyGet(NX_PACKET **packet_ptr) {
    return responseBodyGet(packet_ptr, getTimeout());
}

UINT Client::responseBodyGet(Stm32NetX::Packet &packet) {
    NX_PACKET *packet_ptr{};
    const auto ret = responseBodyGet(&packet_ptr, getTimeout());
    packet = packet_ptr;
    return ret;
}


#if defined(LIBSMART_STM32NETX_ENABLE_TLS) && defined(NX_WEB_HTTPS_ENABLE)




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
                ->printf("metadata_size = %lu  >  sizeof(crypto_metadata) = %lu\r\n", metadata_size,
                         sizeof(crypto_metadata));
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
