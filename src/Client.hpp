/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef LIBSMART_STM32NETXHTTPWEBCLIENT_CLIENT_HPP
#define LIBSMART_STM32NETXHTTPWEBCLIENT_CLIENT_HPP

#include "Secure/X509.hpp"
#include "Loggable.hpp"
#include "Nameable.hpp"
#include "nx_web_http_client.h"


#define NX_WEB_HTTP_SESSION_MAX 1
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;


namespace Stm32NetXHttpWebClient {
    class Client : protected NX_WEB_HTTP_CLIENT, public Stm32ItmLogger::Loggable, public Stm32Common::Nameable {
    public:
        Client() : NX_WEB_HTTP_CLIENT_STRUCT(), Nameable("Stm32NetXHttpWebClient::Client") {
            registerInstance(this);
        }

        UINT create(CHAR *client_name, NX_IP *ip_ptr, NX_PACKET_POOL *pool_ptr, ULONG window_size);

        UINT create();

        UINT del();

        UINT getStart(NXD_ADDRESS *ip_address, UINT server_port, CHAR *resource, CHAR *host, CHAR *username,
                      CHAR *password, ULONG wait_option);


        UINT responseBodyGet(NX_PACKET **packet_ptr, ULONG wait_option);


        UINT connect(NXD_ADDRESS *server_ip, UINT server_port, ULONG wait_option);

    private:
        inline static Client *httpWebClientRegistry[5]{};

        static void registerInstance(const Client *self) {
            assert_param(self != nullptr);
            for (auto &i: httpWebClientRegistry) {
                if (i == nullptr) {
                    i = const_cast<Client *>(self);
                    return;
                }
            }
            assert_param(1==2);
        }

        static void removeInstance(const Client *self) {
            assert_param(self != nullptr);
            for (auto &i: httpWebClientRegistry) {
                if (i != nullptr && i == self) {
                    i = nullptr;
                    return;
                }
            }
            assert_param(1==2);
        }

        static void removeInstance(const NX_WEB_HTTP_CLIENT *web_client_ptr) {
            assert_param(web_client_ptr != nullptr);
            for (auto &i: httpWebClientRegistry) {
                if (i != nullptr && static_cast<NX_WEB_HTTP_CLIENT *>(i) == web_client_ptr) {
                    i = nullptr;
                    return;
                }
            }
            assert_param(1==2);
        }

        static Client *findInstance(const NX_WEB_HTTP_CLIENT *web_client_ptr) {
            assert_param(web_client_ptr != nullptr);
            for (auto &i: httpWebClientRegistry) {
                if (i != nullptr && static_cast<NX_WEB_HTTP_CLIENT *>(i) == web_client_ptr) {
                    return i;
                }
            }
            return nullptr;
        }

        template<class T, class Method, Method m, class... Params>
        static auto bounce(NX_WEB_HTTP_CLIENT *web_client_ptr, Params... params)
            -> decltype(((*reinterpret_cast<T *>(findInstance(web_client_ptr))).*m)(params...)) {
            assert_param(web_client_ptr != nullptr);
            // Find Stm32NetXHttpWebClient::Client instance in registry
            T *httpWebClient = findInstance(web_client_ptr);
            assert_param(httpWebClient != nullptr);
            // BREAKPOINT;
            return ((*reinterpret_cast<T *>(httpWebClient)).*m)(params...);
        }

#if defined(LIBSMART_STM32NETX_ENABLE_TLS) && defined(NX_WEB_HTTPS_ENABLE)

    public:
        UINT getSecureStart(NXD_ADDRESS *ip_address, UINT server_port, CHAR *resource, CHAR *host,
                            CHAR *username, CHAR *password,
                            UINT (*tls_setup)(NX_WEB_HTTP_CLIENT *client_ptr, NX_SECURE_TLS_SESSION *tls_session),
                            ULONG wait_option);

        UINT getSecureStart(NXD_ADDRESS *ip_address, UINT server_port, CHAR *resource, CHAR *host,
                            CHAR *username, CHAR *password,
                            ULONG wait_option);

    private:
        UINT tlsSetupCallback(NX_SECURE_TLS_SESSION *tls_session);

        NX_SECURE_X509_CERT remote_certificate{};
        CHAR crypto_metadata[10128 * NX_WEB_HTTP_SESSION_MAX]{};
        UCHAR tls_packet_buffer[16500]{};
        UCHAR remote_cert_buffer[2000];
        UCHAR remote_issuer_buffer[2000];

#endif
    };
}
#endif
