/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "BaseClient.hpp"
#include <climits>
#include <stdexcept>
#include "Address.hpp"

using namespace Stm32NetXHttpWebClient;

bool BaseClient::isReadyForConnect() {
    return isCreated() && !isConnected() && Stm32NetX::NX->isIpSet();
}

bool BaseClient::isConnected() {
    Stm32NetX::Address peerIpAddress{};
    ULONG peerPort = 0;
    auto const ret = nxd_tcp_socket_peer_info_get(&this->nx_web_http_client_socket, &peerIpAddress, &peerPort);
    if (ret == NX_SUCCESS) {
        flags.set(IS_CONNECTED);
        return true;
    } else {
        flags.clear(IS_CONNECTED);
        return false;
    }
}

bool BaseClient::isCreated() {
    return flags.isSet(IS_CREATED);
}

UINT BaseClient::create(CHAR *client_name, NX_IP *ip_ptr, NX_PACKET_POOL *pool_ptr, ULONG window_size) {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->println("Stm32NetXHttpWebClient::BaseClient::create()");

    if (flags.isSet(IS_CREATED)) {
        return NX_SUCCESS;
    }

    // Clear all flags
    flags.clear(ULONG_MAX);

    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-web-http/chapter3.md#nx_web_http_client_create
    const auto ret = nx_web_http_client_create(static_cast<NX_WEB_HTTP_CLIENT*>(this), client_name, ip_ptr, pool_ptr,
                                               window_size);

    if (ret != NX_SUCCESS) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf("Stm32NetXHttpWebClient::Client[%s]: nx_web_http_client_create() = 0x%02x\r\n",
                         getName(), ret);
#if __EXCEPTIONS
        throw std::runtime_error("nx_web_http_client_create() failed");
#endif
        return ret;
    }

    flags.set(IS_CREATED);

    return ret;
}

UINT BaseClient::del() {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->println("Stm32NetXHttpWebClient::BaseClient::del()");

    if (!flags.isSet(IS_CREATED)) {
        // Clear all flags
        flags.clear(ULONG_MAX);
        return NX_SUCCESS;
    }

    // Clear all flags
    flags.clear(ULONG_MAX);

    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-web-http/chapter3.md#nx_web_http_client_delete
    const auto ret = nx_web_http_client_delete(static_cast<NX_WEB_HTTP_CLIENT *>(this));

    std::memset(static_cast<NX_WEB_HTTP_CLIENT *>(this), 0, sizeof(NX_WEB_HTTP_CLIENT));

    if (ret != NX_SUCCESS) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf("Stm32NetXHttpWebClient::Client[%s]: nx_web_http_client_delete() = 0x%02x\r\n",
                         getName(), ret);
#if __EXCEPTIONS
        throw std::runtime_error("nx_web_http_client_delete() failed");
#endif
        return ret;
    }

    return ret;
}

UINT BaseClient::request_packet_allocate(NX_PACKET **packet_ptr, ULONG wait_option) {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->println("Stm32NetXHttpWebClient::BaseClient::request_packet_allocate()");

    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-web-http/chapter3.md#nx_web_http_client_request_packet_allocate
    const auto ret = nx_web_http_client_request_packet_allocate(
        static_cast<NX_WEB_HTTP_CLIENT *>(this),
        packet_ptr,
        wait_option);

    if (ret != NX_SUCCESS) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf(
                    "Stm32NetXHttpWebClient::Client[%s]: nx_web_http_client_request_packet_allocate() = 0x%02x\r\n",
                    getName(), ret);
#if __EXCEPTIONS
        throw std::runtime_error("nx_web_http_client_request_packet_allocate() failed");
#endif
        return ret;
    }

    flags.set(IS_PACKET_ALLOCATED);

    return ret;
}

UINT BaseClient::request_chunked_set(UINT chunk_size, NX_PACKET *packet_ptr) {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->println("Stm32NetXHttpWebClient::BaseClient::request_chunked_set()");

    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-web-http/chapter3.md#nx_web_http_client_request_chunked_set
    const auto ret = nx_web_http_client_request_chunked_set(
        static_cast<NX_WEB_HTTP_CLIENT *>(this),
        chunk_size,
        packet_ptr);

    if (ret != NX_SUCCESS) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf(
                    "Stm32NetXHttpWebClient::Client[%s]: nx_web_http_client_request_chunked_set() = 0x%02x\r\n",
                    getName(), ret);
#if __EXCEPTIONS
        throw std::runtime_error("nx_web_http_client_request_chunked_set() failed");
#endif
        return ret;
    }

    return ret;
}

UINT BaseClient::request_header_add(CHAR *field_name, UINT name_length, CHAR *field_value, UINT value_length,
                                    UINT wait_option) {
    log()->setSeverity(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->println("Stm32NetXHttpWebClient::BaseClient::request_header_add()");

    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-web-http/chapter3.md#nx_web_http_client_request_header_add
    const auto ret = nx_web_http_client_request_header_add(
        static_cast<NX_WEB_HTTP_CLIENT *>(this),
        field_name, name_length,
        field_value, value_length,
        wait_option);

    if (ret != NX_SUCCESS) {
        log()->setSeverity(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf(
                    "Stm32NetXHttpWebClient::Request[%s]: nx_web_http_client_request_header_add() = 0x%02x\r\n",
                    getName(), ret);
#if __EXCEPTIONS
        throw std::runtime_error("nx_web_http_client_request_header_add() failed");
#endif
        return ret;
    }
    return ret;
}

UINT BaseClient::request_initialize(UINT method, CHAR *resource, CHAR *host, UINT input_size,
                                    UINT transfer_encoding_trunked, CHAR *username, CHAR *password,
                                    UINT wait_option) {
    log()->setSeverity(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->println("Stm32NetXHttpWebClient::BaseClient::client_request_initialize()");

    if (!flags.isSet(IS_CONNECTED)) {
#if __EXCEPTIONS
        throw std::runtime_error("Stm32NetXHttpWebClient not connected");
#endif
        return NX_NOT_CONNECTED;
    }

    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-web-http/chapter3.md#nx_web_http_client_request_initialize
    const auto ret = nx_web_http_client_request_initialize(
        static_cast<NX_WEB_HTTP_CLIENT *>(this),
        method,
        resource,
        host,
        input_size,
        transfer_encoding_trunked,
        username,
        password,
        wait_option);

    if (ret != NX_SUCCESS) {
        log()->setSeverity(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf(
                    "Stm32NetXHttpWebClient::Request[%s]: nx_web_http_client_request_initialize() = 0x%02x\r\n",
                    getName(), ret);
#if __EXCEPTIONS
        throw std::runtime_error("nx_web_http_client_request_initialize() failed");
#endif
        return ret;
    }
    flags.set(IS_INITIALIZED);
    return ret;
}

UINT BaseClient::request_initialize_extended(UINT method, CHAR *resource, UINT resource_length, CHAR *host,
                                             UINT host_length, UINT input_size, UINT transfer_encoding_trunked,
                                             CHAR *username, UINT username_length,
                                             CHAR *password, UINT password_length, UINT wait_option) {
    log()->setSeverity(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->println("Stm32NetXHttpWebClient::BaseClient::request_initialize_extended()");

    if (!flags.isSet(IS_CONNECTED)) {
#if __EXCEPTIONS
        throw std::runtime_error("Stm32NetXHttpWebClient not connected");
#endif
        return NX_NOT_CONNECTED;
    }

    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-web-http/chapter3.md#nx_web_http_client_request_initialize_extended
    const auto ret = nx_web_http_client_request_initialize_extended(
        static_cast<NX_WEB_HTTP_CLIENT *>(this),
        method,
        resource,
        resource_length,
        host,
        host_length,
        input_size,
        transfer_encoding_trunked,
        username,
        username_length,
        password,
        password_length,
        wait_option);

    if (ret != NX_SUCCESS) {
        log()->setSeverity(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf(
                    "Stm32NetXHttpWebClient::Request[%s]: nx_web_http_client_request_initialize_extended() = 0x%02x\r\n",
                    getName(), ret);
#if __EXCEPTIONS
        throw std::runtime_error("nx_web_http_client_request_initialize_extended() failed");
#endif
        return ret;
    }
    flags.set(IS_INITIALIZED);
    return ret;
}

UINT BaseClient::request_packet_send(NX_PACKET *packet_ptr, UINT more_data, ULONG wait_option) {
    log()->setSeverity(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->println("Stm32NetXHttpWebClient::BaseClient::request_packet_send()");

    if (!flags.isSet(IS_INITIALIZED)) {
#if __EXCEPTIONS
        throw std::runtime_error("Stm32NetXHttpWebClient request not initialized");
#endif
        return NX_NOT_SUCCESSFUL;
    }

    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-web-http/chapter3.md#nx_web_http_client_request_packet_send
    const auto ret = nx_web_http_client_request_packet_send(
        static_cast<NX_WEB_HTTP_CLIENT *>(this),
        packet_ptr,
        0,
        wait_option);

    if (ret != NX_SUCCESS) {
        log()->setSeverity(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf(
                    "Stm32NetXHttpWebClient::Request[%s]: nx_web_http_client_request_packet_send() = 0x%02x\r\n",
                    getName(), ret);
#if __EXCEPTIONS
        throw std::runtime_error("nx_web_http_client_request_packet_send() failed");
#endif
        return ret;
    }
    return ret;
}

UINT BaseClient::request_send(UINT wait_option) {
    log()->setSeverity(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->println("Stm32NetXHttpWebClient::BaseClient::request_send()");


    if (!flags.isSet(IS_INITIALIZED)) {
#if __EXCEPTIONS
        throw std::runtime_error("Stm32NetXHttpWebClient request not initialized");
#endif
        return NX_NOT_SUCCESSFUL;
    }


    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-web-http/chapter3.md#nx_web_http_client_request_send
    const auto ret = nx_web_http_client_request_send(static_cast<NX_WEB_HTTP_CLIENT *>(this), wait_option);

    if (ret != NX_SUCCESS) {
        log()->setSeverity(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf(
                    "Stm32NetXHttpWebClient::Request[%s]: nx_web_http_client_request_send() = 0x%02x\r\n",
                    getName(), ret);
#if __EXCEPTIONS
        throw std::runtime_error("nx_web_http_client_request_send() failed");
#endif
        return ret;
    }
    // flags.set(IS_INITIALIZED);
    return ret;
}

UINT BaseClient::response_body_get(NX_PACKET **packet_ptr, ULONG wait_option) {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->println("Stm32NetXHttpWebClient::BaseClient::response_body_get()");

    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-web-http/chapter3.md#nx_web_http_client_response_body_get
    const auto ret = nx_web_http_client_response_body_get(
        static_cast<NX_WEB_HTTP_CLIENT *>(this), packet_ptr, wait_option);

    if (ret != NX_SUCCESS && ret != NX_NO_PACKET && ret != NX_WEB_HTTP_GET_DONE) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf("Stm32NetXHttpWebClient::Client[%s]: nx_web_http_client_response_body_get() = 0x%02x\r\n",
                         getName(), ret);
    }
    return ret;
}

UINT BaseClient::response_header_callback_set(response_header_callback callback_function) {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->println("Stm32NetXHttpWebClient::BaseClient::response_header_callback_set()");

    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-web-http/chapter3.md#nx_web_http_client_response_header_callback_set
    const auto ret = nx_web_http_client_response_header_callback_set(
        static_cast<NX_WEB_HTTP_CLIENT *>(this), callback_function);

    if (ret != NX_SUCCESS && ret != NX_NO_PACKET && ret != NX_WEB_HTTP_GET_DONE) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf(
                    "Stm32NetXHttpWebClient::Client[%s]: nx_web_http_client_response_header_callback_set() = 0x%02x\r\n",
                    getName(), ret);
    }
    return ret;
}

UINT BaseClient::connect(NXD_ADDRESS *server_ip, UINT server_port, ULONG wait_option) {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->println("Stm32NetXHttpWebClient::BaseClient::connect()");

    Stm32NetX::Address serverIpAddress{server_ip};
    if (!serverIpAddress.isValid()) {
#if __EXCEPTIONS
        throw std::runtime_error("Invalid ip address");
#endif
        return NX_IP_ADDRESS_ERROR;
    }

    if (server_port == 0) {
#if __EXCEPTIONS
        throw std::runtime_error("Invalid port");
#endif
        return NX_INVALID_PORT;
    }

    if (!isReadyForConnect()) {
        Stm32NetX::Address peerIpAddress{};
        ULONG peerPort = 0;

        auto const ret = nxd_tcp_socket_peer_info_get(&this->nx_web_http_client_socket, &peerIpAddress, &peerPort);

        if (ret == NX_SUCCESS) {
            // Already connected => check peer
            if (server_port == peerPort && peerIpAddress == serverIpAddress) {
                // Already connected to this server => OK
                return NX_SUCCESS;
            } else {
                // Connected to other peer => ERROR
#if __EXCEPTIONS
                throw std::runtime_error("Connection already established to other peer");
#endif
                return NX_NOT_CREATED;
            }
        } else {
            // Not connected, but not ready for connect => ERROR
#if __EXCEPTIONS
            throw std::runtime_error("Not ready for connection");
#endif
            return NX_NOT_CREATED;
        }
    }

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
#if __EXCEPTIONS
        throw std::runtime_error("nx_web_http_client_connect() failed");
#endif
        return ret;
    }

    flags.set(IS_CONNECTED);
    return ret;
}

UINT BaseClient::secure_connect(NXD_ADDRESS *server_ip, UINT server_port, secure_connect_callback tls_setup,
                                ULONG wait_option) {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->println("Stm32NetXHttpWebClient::BaseClient::secure_connect()");

    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-web-http/chapter3.md#nx_web_http_client_response_header_callback_set
    const auto ret = nx_web_http_client_secure_connect(
        static_cast<NX_WEB_HTTP_CLIENT *>(this), server_ip, server_port, tls_setup, wait_option);

    if (ret != NX_SUCCESS && ret != NX_NO_PACKET && ret != NX_WEB_HTTP_GET_DONE) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf("Stm32NetXHttpWebClient::Client[%s]: nx_web_http_client_secure_connect() = 0x%02x\r\n",
                         getName(), ret);
    }
    return ret;
}
