/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "BaseClient.hpp"
#include "Stm32NetXHttpWebClient.hpp"
#include "Callback/CallbackCapable.hpp"

extern "C" {
#include "nx_web_http_client.h"
}

namespace Stm32NetXHttpWebClient {
    using ResponseHeaderCallbackCapable = Stm32Common::CallbackCapable<void,
        NX_WEB_HTTP_CLIENT *, CHAR *, UINT, CHAR *, UINT>;

    class ResponseHeaderCallback : public ResponseHeaderCallbackCapable {
    public:
        static constexpr const char *COMPONENT_NAME = Stm32NetXHttpWebClient::COMPONENT_NAME;
        static constexpr char CLASS_NAME[] = "ResponseHeaderCallback";
        const char *INSTANCE_NAME;

        BaseClient::ContentLength contentLength{};
        BaseClient::ContentType contentType{};

    private:
        virtual void responseHeaderCallback(BaseClient::HeaderFieldName &name, BaseClient::HeaderFieldValue &value);

        void callback(NX_WEB_HTTP_CLIENT *client_ptr,
                      CHAR *field_name, UINT field_name_length,
                      CHAR *field_value, UINT field_value_length) override;

    };
}
