/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef LIBSMART_STM32NETXHTTPWEBCLIENT_REQUEST_HPP
#define LIBSMART_STM32NETXHTTPWEBCLIENT_REQUEST_HPP

#include "nx_web_http_client.h"

namespace Stm32NetXHttpWebClient {
    class Client;

    class Request {
    public:
        virtual ~Request() = default;

        explicit Request(Client *client)
            : client(client) {
        }

        UINT initialize(UINT method,
                        CHAR *resource,
                        UINT resource_length,
                        CHAR *host,
                        UINT host_length,
                        UINT input_size,
                        UINT transfer_encoding_trunked,
                        CHAR *username,
                        UINT username_length,
                        CHAR *password,
                        UINT password_length,
                        UINT wait_option);

        using HTTP_METHOD = enum : UINT {
            METHOD_NONE = 0,
            METHOD_GET,
            METHOD_PUT,
            METHOD_POST,
            METHOD_DELETE,
            METHOD_HEAD
        };

        UINT initialize(HTTP_METHOD method, const CHAR *resource, const CHAR *host, const UINT input_size,
                        const CHAR *username, const CHAR *password);

        UINT initialize(HTTP_METHOD method, const CHAR *resource, const CHAR *host, const UINT input_size);
        UINT initialize(HTTP_METHOD method, const CHAR *resource, const CHAR *host);

        UINT send(UINT wait_option);

        UINT headerAdd(CHAR *field_name,
                       UINT name_length,
                       CHAR *field_value,
                       UINT value_length,
                       UINT wait_option);

        UINT headerAdd(const char *field_name, const char *field_value);

        UINT packetAllocate(NX_PACKET **packet_ptr, ULONG wait_option);

        UINT packetSend(NX_PACKET *packet_ptr,
                        UINT more_date,
                        ULONG wait_option);

        // UINT chunkedSet();

    protected:
        Client *client;
    };
}
#endif
