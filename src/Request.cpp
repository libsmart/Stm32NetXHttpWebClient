/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "Request.hpp"

UINT Stm32NetXHttpWebClient::Request::initialize(UINT method, CHAR *resource, UINT resource_length, CHAR *host,
                                                 UINT host_length, UINT input_size, UINT transfer_encoding_trunked,
                                                 CHAR *username, UINT username_length,
                                                 CHAR *password, UINT password_length, UINT wait_option) {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->println("Stm32NetXHttpWebClient::Request::initialize()");

    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-web-http/chapter3.md#nx_web_http_client_request_initialize_extended
    const auto ret = nx_web_http_client_request_initialize_extended(this,
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
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf(
                    "Stm32NetXHttpWebClient::Request[%s]: nx_web_http_client_request_initialize_extended() = 0x%02x\r\n",
                    getName(), ret);
    }
    flags.set(IS_INITIALIZED);
    return ret;
}

UINT Stm32NetXHttpWebClient::Request::initialize(HTTP_METHOD method, const CHAR *resource, const CHAR *host,
    const UINT input_size, const CHAR *username, const CHAR *password) {
    return initialize(method, const_cast<CHAR *>(resource), strlen(resource),
        const_cast<CHAR *>(host), strlen(host), input_size, 0,
        const_cast<CHAR *>(username), username == nullptr ? 0 : strlen(username),
        const_cast<CHAR *>(password), password == nullptr ? 0 : strlen(password),
        NX_NO_WAIT);
}

UINT Stm32NetXHttpWebClient::Request::initialize(HTTP_METHOD method, const CHAR *resource, const CHAR *host,
    const UINT input_size) {
    return initialize(method, resource, host, input_size, nullptr, nullptr);
}

UINT Stm32NetXHttpWebClient::Request::initialize(HTTP_METHOD method, const CHAR *resource, const CHAR *host) {
    return initialize(method, resource, host, 0);
}

UINT Stm32NetXHttpWebClient::Request::send(UINT wait_option) {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->println("Stm32NetXHttpWebClient::Request::send()");

    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-web-http/chapter3.md#nx_web_http_client_request_send
    const auto ret = nx_web_http_client_request_send(this, wait_option);

    if (ret != NX_SUCCESS) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf(
                    "Stm32NetXHttpWebClient::Request[%s]: nx_web_http_client_request_send() = 0x%02x\r\n",
                    getName(), ret);
    }
    // flags.set(IS_INITIALIZED);
    return ret;
}

UINT Stm32NetXHttpWebClient::Request::headerAdd(CHAR *field_name, UINT name_length, CHAR *field_value,
                                                UINT value_length, UINT wait_option) {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->println("Stm32NetXHttpWebClient::Request::headerAdd()");

    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-web-http/chapter3.md#nx_web_http_client_request_header_add
    const auto ret = nx_web_http_client_request_header_add(this, field_name, name_length, field_value, value_length,
                                                           wait_option);

    if (ret != NX_SUCCESS) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf(
                    "Stm32NetXHttpWebClient::Request[%s]: nx_web_http_client_request_header_add() = 0x%02x\r\n",
                    getName(), ret);
    }
    return ret;
}

UINT Stm32NetXHttpWebClient::Request::headerAdd(const char *field_name, const char *field_value) {
    return headerAdd(const_cast<char *>(field_name), strlen(field_name),
                     const_cast<char *>(field_value), strlen(field_value), NX_NO_WAIT);
}

UINT Stm32NetXHttpWebClient::Request::packetAllocate(NX_PACKET **packet_ptr, ULONG wait_option) {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->println("Stm32NetXHttpWebClient::Request::packetAllocate()");

    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-web-http/chapter3.md#nx_web_http_client_request_packet_allocate
    const auto ret = nx_web_http_client_request_packet_allocate(this, packet_ptr, wait_option);

    if (ret != NX_SUCCESS) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf(
                    "Stm32NetXHttpWebClient::Request[%s]: nx_web_http_client_request_packet_allocate() = 0x%02x\r\n",
                    getName(), ret);
    }
    return ret;
}

UINT Stm32NetXHttpWebClient::Request::packetSend(NX_PACKET *packet_ptr, UINT more_date, ULONG wait_option) {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->println("Stm32NetXHttpWebClient::Request::packetSend()");

    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-web-http/chapter3.md#nx_web_http_client_request_packet_send
    const auto ret = nx_web_http_client_request_packet_send(this, packet_ptr, 0, wait_option);

    if (ret != NX_SUCCESS) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf(
                    "Stm32NetXHttpWebClient::Request[%s]: nx_web_http_client_request_packet_send() = 0x%02x\r\n",
                    getName(), ret);
    }
    return ret;
}
