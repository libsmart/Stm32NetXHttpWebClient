/*
 * SPDX-FileCopyrightText: 2026 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "Loggable.hpp"
#include "Callback/CallbackCapable.hpp"

extern "C" {
#include "nx_web_http_client.h"
}

#define NX_WEB_HTTP_SESSION_MAX 1

namespace Stm32NetXHttpWebClient {
    class Client;
    using tlsSetupCallbackCapable = Stm32Common::CallbackCapable<UINT,
        NX_WEB_HTTP_CLIENT *, NX_SECURE_TLS_SESSION *>;

    class TlsSetupCallback : public Stm32ItmLogger::Loggable, public tlsSetupCallbackCapable {
    public:
        TlsSetupCallback() = delete;

        explicit TlsSetupCallback(Client &client);

        ~TlsSetupCallback() override = default;

        NX_SECURE_X509_DNS_NAME dns_name{};

    protected:
        virtual UINT tlsSetupCallback(NX_SECURE_TLS_SESSION_STRUCT *tls_session);
        Client & getWebClient() const;

    private:
        Client &webClient;

        UINT callback(NX_WEB_HTTP_CLIENT_STRUCT *, NX_SECURE_TLS_SESSION_STRUCT *) override;



        CHAR crypto_metadata[1024 * 15 * NX_WEB_HTTP_SESSION_MAX]{};
        UCHAR tls_packet_buffer[32 * 1024]{};

        NX_SECURE_X509_CERT remote_certificate{};
        UCHAR remote_cert_buffer[4 * 1024]{};

        // NX_SECURE_X509_CERT remote_issuer{};
        // UCHAR remote_issuer_buffer[4 * 1024]{};

    };
}
