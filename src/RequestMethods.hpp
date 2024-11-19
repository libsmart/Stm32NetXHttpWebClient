/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <Request.hpp>
#include <variant>

namespace Stm32NetXHttp {
    namespace Method {
        struct NONE {
            explicit operator const char *() const { return "NONE"; }
            explicit operator Stm32NetXHttpWebClient::Request::HTTP_METHOD() const { return Stm32NetXHttpWebClient::Request::METHOD_NONE; }
            explicit operator UINT() const { return getId(); }
            UINT getId() const { return NX_WEB_HTTP_METHOD_NONE; }
        };

        struct GET {
            explicit operator const char *() const { return "GET"; }
            explicit operator Stm32NetXHttpWebClient::Request::HTTP_METHOD() const { return Stm32NetXHttpWebClient::Request::METHOD_GET; }
            explicit operator UINT() const { return getId(); }
            UINT getId() const { return NX_WEB_HTTP_METHOD_GET; }
        };

        struct PUT {
            explicit operator const char *() const { return "PUT"; }
            explicit operator Stm32NetXHttpWebClient::Request::HTTP_METHOD() const { return Stm32NetXHttpWebClient::Request::METHOD_PUT; }
            explicit operator UINT() const { return getId(); }
            UINT getId() const { return NX_WEB_HTTP_METHOD_PUT; }
        };

        struct POST {
            explicit operator const char *() const { return "POST"; }
            explicit operator Stm32NetXHttpWebClient::Request::HTTP_METHOD() const { return Stm32NetXHttpWebClient::Request::METHOD_POST; }
            explicit operator UINT() const { return getId(); }
            UINT getId() const { return NX_WEB_HTTP_METHOD_POST; }
        };

        struct DELETE {
            explicit operator const char *() const { return "DELETE"; }
            explicit operator Stm32NetXHttpWebClient::Request::HTTP_METHOD() const { return Stm32NetXHttpWebClient::Request::METHOD_DELETE; }
            explicit operator UINT() const { return getId(); }
            UINT getId() const { return NX_WEB_HTTP_METHOD_DELETE; }
        };

        struct HEAD {
            explicit operator const char *() const { return "HEAD"; }
            explicit operator Stm32NetXHttpWebClient::Request::HTTP_METHOD() const { return Stm32NetXHttpWebClient::Request::METHOD_HEAD; }
            explicit operator UINT() const { return getId(); }
            UINT getId() const { return NX_WEB_HTTP_METHOD_HEAD; }
        };
    }

    using Methods = std::variant<
        Method::NONE,
        Method::GET,
        Method::PUT,
        Method::POST,
        Method::DELETE,
        Method::HEAD
    >;
}