/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <variant>

using namespace Stm32NetXHttpWebClient;

namespace Stm32NetXHttp {
    namespace Method {
        struct NONE {
            explicit operator const char *() const { return "NONE"; }
            explicit operator BaseClient::HTTP_METHOD() const { return BaseClient::METHOD_NONE; }
            explicit operator UINT() const { return getId(); }
            UINT getId() const { return NX_WEB_HTTP_METHOD_NONE; }
        };

        struct GET {
            explicit operator const char *() const { return "GET"; }
            explicit operator BaseClient::HTTP_METHOD() const { return BaseClient::METHOD_GET; }
            explicit operator UINT() const { return getId(); }
            UINT getId() const { return NX_WEB_HTTP_METHOD_GET; }
        };

        struct PUT {
            explicit operator const char *() const { return "PUT"; }
            explicit operator BaseClient::HTTP_METHOD() const { return BaseClient::METHOD_PUT; }
            explicit operator UINT() const { return getId(); }
            UINT getId() const { return NX_WEB_HTTP_METHOD_PUT; }
        };

        struct POST {
            explicit operator const char *() const { return "POST"; }
            explicit operator BaseClient::HTTP_METHOD() const { return BaseClient::METHOD_POST; }
            explicit operator UINT() const { return getId(); }
            UINT getId() const { return NX_WEB_HTTP_METHOD_POST; }
        };

        struct DELETE {
            explicit operator const char *() const { return "DELETE"; }
            explicit operator BaseClient::HTTP_METHOD() const { return BaseClient::METHOD_DELETE; }
            explicit operator UINT() const { return getId(); }
            UINT getId() const { return NX_WEB_HTTP_METHOD_DELETE; }
        };

        struct HEAD {
            explicit operator const char *() const { return "HEAD"; }
            explicit operator BaseClient::HTTP_METHOD() const { return BaseClient::METHOD_HEAD; }
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

    namespace Method {
        inline Methods byId(UINT id) {
            static const std::unordered_map<UINT, Methods> methodMap = {
                {NX_WEB_HTTP_METHOD_NONE, Method::NONE{}},
                {NX_WEB_HTTP_METHOD_GET, Method::GET{}},
                {NX_WEB_HTTP_METHOD_PUT, Method::PUT{}},
                {NX_WEB_HTTP_METHOD_POST, Method::POST{}},
                {NX_WEB_HTTP_METHOD_DELETE, Method::DELETE{}},
                {NX_WEB_HTTP_METHOD_HEAD, Method::HEAD{}}
            };

            auto it = methodMap.find(id);
            if (it != methodMap.end()) {
                return it->second;
            }
#if __EXCEPTIONS
            throw std::invalid_argument("Invalid HTTP method ID");
#endif
            return Method::NONE{};
        }
    }
}
