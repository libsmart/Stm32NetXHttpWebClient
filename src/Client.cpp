/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "Client.hpp"
#include <climits>
#include <thread>

#include "Address/Address.hpp"
#include "Stm32NetX.hpp"

using namespace Stm32NetXHttpWebClient;

bool Client::acquire() {
    const auto ret = semaphore.get(getTimeout());
    if (ret != NX_SUCCESS) {
        constexpr char fmt[] = "Stm32NetXHttpWebClient::Client[%s]: WebClient is busy";
        LIBSMART_HANDLE_ERROR(fmt, getName());
        return false;
    }
    return true;
}

bool Client::release() {
    const auto ret = semaphore.ceiling_put(1);
    return ret == NX_SUCCESS;
}

bool Client::isReleased() {
    ULONG count;
    const auto ret = semaphore.info_get(nullptr, &count, nullptr, nullptr, nullptr);
    return ret == NX_SUCCESS && count == 1;
}

UINT Client::create() {
    // if (!acquire()) return NX_CANNOT_START;
    return BaseClient::create(
        getNameNonConst(),
        Stm32NetX::NX->getIpInstance(),
        Stm32NetX::NX->getPacketPool(),
        LIBSMART_STM32NETXHTTPWEBCLIENT_WINDOW_SIZE);
}

UINT Client::del() {
    const auto ret = BaseClient::del();
    if (!isReleased()) release();
    return ret;
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

UINT Client::packetSend(Stm32NetX::Packet &packet) {
    const auto ret = request_packet_send(static_cast<NX_PACKET *>(packet), 0, getTimeout());
    if (ret == NX_SUCCESS) {
        packet.forget();
    }
    return ret;
}

UINT Client::send() {
    return request_send(getTimeout());
}

UINT Client::connect(const Stm32NetX::Uri &uri) {
    Stm32NetX::Address peerIpAddress{};

    UINT peerPort = uri.get_port();
    if (uri.get_scheme() == "http") {
        useTls = false;
        peerPort = peerPort == 0 ? LIBSMART_STM32NETXHTTPWEBCLIENT_HTTP_PORT : peerPort;
    }
    if (uri.get_scheme() == "https") {
        useTls = true;
        peerPort = peerPort == 0 ? LIBSMART_STM32NETXHTTPWEBCLIENT_HTTPS_PORT : peerPort;
    }

    peerIpAddress = uri.get_host().c_str();
    if (!peerIpAddress.isValid()) {
        // IP not valid => try dns
        Stm32NetX::Dns *dns = Stm32NetX::NX->getDns();
        volatile auto const ret = dns->hostByNameGet(const_cast<CHAR *>(uri.get_host().c_str()), &peerIpAddress,
                                                     getTimeout(), NX_IP_VERSION_V4);
    }

#if defined(LIBSMART_STM32NETX_ENABLE_TLS) && defined(NX_WEB_HTTPS_ENABLE)
    if (useTls) {
        // Set dns_name for SNI
        const auto &host = uri.get_host().c_str();
        auto &dns_name = tlsSetupCb->dns_name;

        memset(&dns_name, 0, sizeof(dns_name));
        const auto len = std::min(strlen(host), static_cast<size_t>(NX_SECURE_X509_DNS_NAME_MAX - 1));
        memcpy(dns_name.nx_secure_x509_dns_name, host, len);
        dns_name.nx_secure_x509_dns_name_length = static_cast<USHORT>(len);
        dns_name.nx_secure_x509_dns_name_next = NX_NULL;
    }
#endif
    return BaseClient::connect(&peerIpAddress, peerPort, getTimeout());
}

void Client::initializeRequest(Stm32NetXHttp::Methods method, const Stm32NetX::Uri &uri, UINT input_size) {
    log()->setSeverity(Stm32ItmLogger::LoggerInterface::Severity::DEBUGGING)
            ->printf("Stm32NetXHttpWebClient::Client::initializeRequest(%s, \"%s\", %d)\r\n",
                     std::visit([](auto &arg) -> auto { return static_cast<const char *>(arg); }, method),
                     uri.to_string().c_str(),
                     input_size
            );

    // log()->printf("method: 0x%02x\r\n", std::visit([](auto &arg) -> auto { return (UINT) arg; }, method));
    // log()->printf("method: %s\r\n", std::visit([](auto &arg) -> auto { return (const char *) arg; }, method));
    // log()->printf("uri: %s\r\n", uri.to_string().c_str());
    // log()->printf("scheme: %s\r\n", uri.get_scheme().c_str());
    // log()->printf("host: %s\r\n", uri.get_host().c_str());

    initialize(
        std::visit([](auto &arg) -> auto { return static_cast<HTTP_METHOD>(arg); }, method),
        uri.get_resource().c_str(),
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

