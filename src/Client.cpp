/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "Client.hpp"

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
    return ret;
}

UINT Client::create() {
    return create(getNameNonConst(), Stm32NetX::NX->getIpInstance(), Stm32NetX::NX->getPacketPool(), 8*1024);
}


UINT Client::del() {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->println("Stm32NetXHttpWebClient::Client::del()");

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
    return ret;
}
