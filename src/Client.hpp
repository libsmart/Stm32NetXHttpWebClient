/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef LIBSMART_STM32NETXHTTPWEBCLIENT_CLIENT_HPP
#define LIBSMART_STM32NETXHTTPWEBCLIENT_CLIENT_HPP

#include "Loggable.hpp"
#include "Nameable.hpp"
#include "nx_web_http_client.h"

namespace Stm32NetXHttpWebClient {
    class Client : protected NX_WEB_HTTP_CLIENT, public Stm32ItmLogger::Loggable, public Stm32Common::Nameable {
    public:
        UINT create(CHAR *client_name, NX_IP *ip_ptr, NX_PACKET_POOL *pool_ptr, ULONG window_size);

        UINT create();

        UINT del();

        UINT getStart(NXD_ADDRESS *ip_address, UINT server_port, CHAR *resource, CHAR *host, CHAR *username,
                      CHAR *password, ULONG wait_option);


        UINT responseBodyGet(NX_PACKET **packet_ptr, ULONG wait_option);


        UINT connect(NXD_ADDRESS *server_ip, UINT server_port, ULONG wait_option);
    };
}
#endif
