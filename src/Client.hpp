/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef LIBSMART_STM32NETXHTTPWEBCLIENT_CLIENT_HPP
#define LIBSMART_STM32NETXHTTPWEBCLIENT_CLIENT_HPP

#include <BaseClient.hpp>

#include "EventFlags.hpp"
#include "Secure/X509.hpp"
#include "Loggable.hpp"
#include "Nameable.hpp"
#include "nx_web_http_client.h"
#include "Address/Uri.hpp"
#include "RequestMethods.hpp"
#include "Packet/Packet.hpp"


#define NX_WEB_HTTP_SESSION_MAX 1

#if defined(LIBSMART_STM32NETX_ENABLE_TLS) && defined(NX_WEB_HTTPS_ENABLE)
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;
#endif

namespace Stm32NetXHttpWebClient {
    class Client : public BaseClient {
        friend class Request;

    public:
        Client() = default;

        /*
        explicit Client(Stm32NetX::NetX *nx)
            : BaseClient(nx) { ; }

        Client(Stm32NetX::NetX *nx, Stm32ItmLogger::LoggerInterface *logger)
            : BaseClient(nx, logger) { ; }

        Client(Stm32NetX::NetX *nx, const char *name)
            : BaseClient(nx, name) { ; }

        Client(Stm32NetX::NetX *nx, const char *name, Stm32ItmLogger::LoggerInterface *logger)
            : BaseClient(nx, name, logger) { ; }
            */


        /**
         * @brief Creates an HTTP client instance.
         *
         * Initializes an HTTP client with the specified name, IP instance, packet pool, and window size.
         *
         * @return The return value is of type UINT. It returns NX_SUCCESS on successful creation of the client,
         *         otherwise an error code.
         */
        UINT create();


        UINT packetAllocate(NX_PACKET **packet_ptr);

        UINT packetAllocate(Stm32NetX::Packet &packet);

        UINT headerAdd(const char *field_name, const char *field_value);


        UINT initialize(HTTP_METHOD method, const CHAR *resource, const CHAR *host, const UINT input_size,
                        const CHAR *username, const CHAR *password);

        UINT initialize(HTTP_METHOD method, const CHAR *resource, const CHAR *host, const UINT input_size);

        UINT initialize(HTTP_METHOD method, const CHAR *resource, const CHAR *host);


        UINT packetSend(Stm32NetX::Packet &packet);

        UINT send();


        UINT connect(const Stm32NetX::Uri &uri);

        void initializeRequest(Stm32NetXHttp::Methods method, const Stm32NetX::Uri &uri, UINT input_size);

        void requestStart(Stm32NetXHttp::Methods method, const Stm32NetX::Uri &uri);

        void requestStart(Stm32NetXHttp::Methods method, const Stm32NetX::Uri &uri, UINT input_size);


        ULONG getTimeout() { return LIBSMART_STM32NETXHTTPWEBCLIENT_TIMEOUT; }

        UINT responseBodyGet(NX_PACKET **packet_ptr, ULONG wait_option);

        UINT responseBodyGet(NX_PACKET **packet_ptr);

        UINT responseBodyGet(Stm32NetX::Packet &packet);


        UINT awaitFlag(const ULONG requestedFlags) { return flags.await(requestedFlags); }

    protected:
        // Stm32ThreadX::EventFlags flags{"Stm32NetXHttpWebClient::Client::flags", getLogger()};


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

    private:
        UINT tlsSetupCallback(NX_SECURE_TLS_SESSION *tls_session);

        NX_SECURE_X509_CERT remote_certificate{};
        CHAR crypto_metadata[10128 * NX_WEB_HTTP_SESSION_MAX]{};
        UCHAR tls_packet_buffer[16500]{};
        UCHAR remote_cert_buffer[2000]{};
        UCHAR remote_issuer_buffer[2000]{};

#endif
    };
}
#endif
