/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef LIBSMART_STM32NETXHTTPWEBCLIENT_CLIENT_HPP
#define LIBSMART_STM32NETXHTTPWEBCLIENT_CLIENT_HPP

#include "EventFlags.hpp"
#include "Secure/X509.hpp"
#include "Loggable.hpp"
#include "Nameable.hpp"
#include "nx_web_http_client.h"
#include "Uri.hpp"
#include "RequestMethods.hpp"
#include "Request.hpp"


#define NX_WEB_HTTP_SESSION_MAX 1

#if defined(LIBSMART_STM32NETX_ENABLE_TLS) && defined(NX_WEB_HTTPS_ENABLE)
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;
#endif

namespace Stm32NetXHttpWebClient {
    class Client : protected NX_WEB_HTTP_CLIENT, public Stm32ItmLogger::Loggable, public Stm32Common::Nameable {
    public:
        Client() : NX_WEB_HTTP_CLIENT_STRUCT(), Nameable("Stm32NetXHttpWebClient::Client") {
            registerInstance(this);
        }

        friend class Request;

        using Flags = enum: ULONG {
            NONE = 0,
            IS_CREATED = 1UL << 0,
            IS_CONNECTED = 1UL << 1,
            IS_INITIALIZED = 1UL << 2,
            THE_END = 1UL << 31
        };

        /**
         * @brief Creates an HTTP client.
         *
         * This function initializes an HTTP client instance with the specified name, IP,
         * packet pool, and window size.
         *
         * @param client_name Pointer to the name of the client.
         * @param ip_ptr Pointer to the NX_IP structure.
         * @param pool_ptr Pointer to the NX_PACKET_POOL structure.
         * @param window_size Size of the window.
         * @return The return value is of type UINT. It returns NX_SUCCESS on successful creation of the client,
         *         otherwise it returns an error code.
         */
        UINT create(CHAR *client_name, NX_IP *ip_ptr, NX_PACKET_POOL *pool_ptr, ULONG window_size);

        /**
         * @brief Creates an HTTP client instance.
         *
         * Initializes an HTTP client with the specified name, IP instance, packet pool, and window size.
         *
         * @return The return value is of type UINT. It returns NX_SUCCESS on successful creation of the client,
         *         otherwise an error code.
         */
        UINT create();

        /**
         * @brief Deletes the HTTP client instance.
         *
         * This method deletes the HTTP client instance if it has been created. It clears all associated flags
         * and calls the underlying NetX Duo function to delete the client. If the client was not created, it
         * simply returns success. Any errors encountered during the deletion process are logged.
         *
         * @return The return value is of type UINT. It returns NX_SUCCESS if the client was successfully deleted
         *         or if the client was not created. In case of errors during deletion, a corresponding error code is returned.
         */
        UINT del();


        /**
         * @brief Checks if the client is ready to establish a connection.
         *
         * This method determines if the client is in a state where it is ready to connect by
         * verifying that the client is created, not currently connected, and that the IP is set.
         *
         * @return Returns true if the client is ready to connect; otherwise, returns false.
         */
        bool isReadyForConnect();


        bool isConnected();
        bool isCreated();


        /**
         * @brief Connects to an HTTP server.
         *
         * This function establishes a connection to the specified HTTP server using the provided
         * server IP address, server port, and wait option.
         *
         * @param server_ip Pointer to the NXD_ADDRESS structure containing the server's IP address.
         * @param server_port The port number of the server.
         * @param wait_option Specifies the behavior for waiting if the connection cannot be established immediately.
         * @return The return value is of type UINT. It returns NX_SUCCESS on successful connection to the server,
         *         otherwise it returns an error code.
         */
        UINT connect(NXD_ADDRESS *server_ip, UINT server_port, ULONG wait_option);

        UINT connect(const Stm32NetX::Uri& uri);

        Request *initializeRequest(Stm32NetXHttp::Methods method, const Stm32NetX::Uri& uri);

        Request *requestStart(Stm32NetXHttp::Methods method, const Stm32NetX::Uri& uri);


        ULONG getTimeout() {return LIBSMART_STM32NETXHTTPWEBCLIENT_TIMEOUT;}




        UINT getStart(NXD_ADDRESS *ip_address, UINT server_port, CHAR *resource, CHAR *host, CHAR *username,
                      CHAR *password, ULONG wait_option);


        UINT responseBodyGet(NX_PACKET **packet_ptr, ULONG wait_option);


        UINT awaitFlag(const ULONG requestedFlags) { return flags.await(requestedFlags); }

    protected:
        Stm32ThreadX::EventFlags flags{"Stm32NetXHttpWebClient::Client::flags", getLogger()};
        Request request{this};

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
        UCHAR remote_cert_buffer[2000]{};
        UCHAR remote_issuer_buffer[2000]{};

#endif
    };
}
#endif
