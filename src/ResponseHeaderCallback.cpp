/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ResponseHeaderCallback.hpp"
#include "Stm32ItmLogger.hpp"

using namespace Stm32NetXHttpWebClient;

void ResponseHeaderCallback::responseHeaderCallback(BaseClient::HeaderFieldName &name,
                                                    BaseClient::HeaderFieldValue &value) {
    if (name == "Content-Length") {
        contentLength = strtoull(value.c_str(), nullptr, 10);
    }
    if (name == "Content-Type") {
        contentType.set(value);
    }
}

void ResponseHeaderCallback::callback(NX_WEB_HTTP_CLIENT *client_ptr,
                                      CHAR *field_name, const UINT field_name_length,
                                      CHAR *field_value, const UINT field_value_length) {
    Stm32ItmLogger::logger.setSeverity(Stm32ItmLogger::LoggerInterface::Severity::WARNING);
    Stm32ItmLogger::logger.printf("%.*s : %.*s\r\n", field_name_length, field_name, field_value_length, field_value);

    BaseClient::HeaderFieldName name{field_name, field_name_length};
    BaseClient::HeaderFieldValue value{field_value, field_value_length};

    responseHeaderCallback(name, value);
}
