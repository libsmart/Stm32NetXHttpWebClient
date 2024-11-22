/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "nx_web_http_client.h"
#include "Loggable.hpp"
#include "Nameable.hpp"
#include "EventFlags.hpp"
#include "Stm32NetX.hpp"

namespace Stm32NetXHttpWebClient {
    class BaseClient : protected NX_WEB_HTTP_CLIENT, public Stm32ItmLogger::Loggable, public Stm32Common::Nameable {
        friend class Request;

    public:
        using Flags = enum: ULONG {
            NONE = 0,
            IS_CREATED = 1UL << 0,
            IS_CONNECTED = 1UL << 1,
            IS_INITIALIZED = 1UL << 2,
            IS_PACKET_ALLOCATED = 1UL << 3,
            THE_END = 1UL << 31
        };

        using HTTP_METHOD = enum : UINT {
            METHOD_NONE = 0,
            METHOD_GET,
            METHOD_PUT,
            METHOD_POST,
            METHOD_DELETE,
            METHOD_HEAD
        };


        BaseClient() : NX_WEB_HTTP_CLIENT() { ; }

        /*
        explicit BaseClient(Stm32NetX::NetX *nx)
            : BaseClient(nx, "Stm32NetXHttpWebClient", &Stm32ItmLogger::emptyLogger) {
        }

        BaseClient(Stm32NetX::NetX *nx, Stm32ItmLogger::LoggerInterface *logger)
            : BaseClient(nx, "Stm32NetXHttpWebClient", logger) { ; }

        BaseClient(Stm32NetX::NetX *nx, const char *name)
            : BaseClient(nx, name, &Stm32ItmLogger::emptyLogger) { ; }

        BaseClient(Stm32NetX::NetX *nx, const char *name, Stm32ItmLogger::LoggerInterface *logger)
            : Loggable(logger), Nameable(name), nx(nx), NX_WEB_HTTP_CLIENT() { ; }
*/

        bool isReadyForConnect();

        bool isConnected();

        bool isCreated();


        /**
         * Creates a new HTTP client instance.
         *
         * @param client_name Name of the client to create.
         * @param ip_ptr Pointer to the IP instance.
         * @param pool_ptr Pointer to the packet pool.
         * @param window_size Size of the window.
         * @return NX_SUCCESS if creation is successful, error code otherwise.
         * @throws std::runtime_error if creation fails and exceptions are enabled.
         *
         * Creates an HTTP client by initializing it with the provided parameters.
         * Ensures the client is not already created and sets the necessary flags.
         * Logs informational and error messages.
         */
        virtual UINT create(CHAR *client_name, NX_IP *ip_ptr, NX_PACKET_POOL *pool_ptr, ULONG window_size);

        /**
         * Deletes the HTTP client instance.
         *
         * @return NX_SUCCESS if the deletion is successful, error code otherwise.
         *
         * Logs the deletion attempt and clears all flags. If the instance was not created,
         * it clears all flags and returns NX_SUCCESS. Uses nx_web_http_client_delete to
         * delete the client and resets the client instance memory.
         * Throws a runtime error if the deletion fails (only if exceptions are enabled).
         */
        virtual UINT del();

        /**
         * Allocates an HTTP request packet for the client.
         *
         * @param packet_ptr Pointer to the allocated packet.
         * @param wait_option Specifies the behavior of the allocation if resources are not immediately available.
         * @return NX_SUCCESS if allocation is successful, error code otherwise.
         * @throws std::runtime_error if allocation fails and exceptions are enabled.
         *
         * Allocates a packet for HTTP requests to be used by the client. On successful allocation,
         * the packet is prepared for further HTTP operations and necessary flags are set.
         * Logs informational messages on the process and error messages if the allocation fails.
         */
        virtual UINT request_packet_allocate(NX_PACKET **packet_ptr, ULONG wait_option);

        /**
         * Sets the chunked transfer encoding for an HTTP request.
         *
         * @param chunk_size Size of the chunks to be used.
         * @param packet_ptr Pointer to the packet to be used.
         * @return NX_SUCCESS if the chunked transfer is successfully set, error code otherwise.
         *
         * Configures the HTTP client for chunked transfer encoding using the specified chunk size and packet pointer.
         * Logs informational messages upon invocation and error messages if the configuration fails.
         * This method may throw a runtime error if exceptions are enabled and the configuration fails.
         */
        virtual UINT request_chunked_set(UINT chunk_size, NX_PACKET *packet_ptr);

        /**
         * Adds a header field to the HTTP request.
         *
         * @param field_name Name of the header field to add.
         * @param name_length Length of the header field name.
         * @param field_value Value of the header field.
         * @param value_length Length of the header field value.
         * @param wait_option Option to wait if the header cannot be added immediately.
         * @return NX_SUCCESS if successful, error code otherwise.
         *
         * This method logs the operation and, on failure, logs an error message. It may also throw a
         * runtime exception if exceptions are enabled and the operation fails.
         */
        virtual UINT request_header_add(CHAR *field_name, UINT name_length, CHAR *field_value, UINT value_length,
                                        UINT wait_option);

        /**
         * Initializes an HTTP request for the BaseClient.
         *
         * @param method The HTTP method to use (e.g., GET, POST).
         * @param resource The resource path of the request.
         * @param host The host to which the request is made.
         * @param input_size The size of the input data being sent.
         * @param transfer_encoding_trunked Specifies if transfer encoding is chunked.
         * @param username The username for authentication, if required.
         * @param password The password for authentication, if required.
         * @param wait_option Option that specifies how long to wait for the request's completion.
         * @return NX_SUCCESS if the request is successfully initialized, error code otherwise.
         * @throws std::runtime_error if the client is not connected or initialization fails.
         *
         * Prepares the HTTP client to send a request by configuring necessary parameters.
         * Checks connection status before proceeding, logs actions, and sets initialization flags.
         * @deprecated
         */
        virtual UINT request_initialize(UINT method, CHAR *resource, CHAR *host, UINT input_size,
                                        UINT transfer_encoding_trunked, CHAR *username, CHAR *password,
                                        UINT wait_option);

        /**
         * Initializes an HTTP client request with extended parameters.
         *
         * @param method HTTP method to use for the request (e.g., GET, POST).
         * @param resource Pointer to the resource path.
         * @param resource_length Length of the resource path.
         * @param host Pointer to the host name.
         * @param host_length Length of the host name.
         * @param input_size Expected size of the input data.
         * @param transfer_encoding_trunked Flag indicating if the transfer encoding is chunked.
         * @param username Pointer to the username for authentication.
         * @param username_length Length of the username.
         * @param password Pointer to the password for authentication.
         * @param password_length Length of the password.
         * @param wait_option Option specifying the wait time.
         * @return NX_SUCCESS if the request initialization is successful, error code otherwise.
         * @throws std::runtime_error if the client is not connected or request initialization fails and exceptions are enabled.
         *
         * This method will initialize an HTTP request with extended parameters, ensuring all necessary
         * fields are set. Logs both informational and error messages as part of the operation.
         */
        virtual UINT request_initialize_extended(UINT method, CHAR *resource, UINT resource_length,
                                                 CHAR *host, UINT host_length, UINT input_size,
                                                 UINT transfer_encoding_trunked,
                                                 CHAR *username, UINT username_length, CHAR *password,
                                                 UINT password_length, UINT wait_option);

        /**
         * Sends an HTTP request packet.
         *
         * @param packet_ptr Pointer to the packet to be sent.
         * @param more_data Indicator if more data will be sent (typically 0 or 1).
         * @param wait_option Option indicating how long to wait for the send to complete.
         * @return NX_SUCCESS if the packet was sent successfully, error code otherwise.
         * @throws std::runtime_error if the client is not initialized or packet send fails and exceptions are enabled.
         *
         * This method sends a packet as part of an HTTP request using the NetX Duo stack.
         * It logs the operation and checks if the client is initialized before the send attempt.
         * If the send fails, an error is logged and an exception is thrown (if enabled).
         */
        virtual UINT request_packet_send(NX_PACKET *packet_ptr, UINT more_data, ULONG wait_option);

        /**
         * Sends an HTTP request using the BaseClient.
         *
         * @param wait_option Specifies the wait option, defining how long to wait if the request cannot be sent immediately.
         * @return NX_SUCCESS if the request is successfully sent, an error code otherwise.
         * @throws std::runtime_error if the client is not initialized or if the request sending fails and exceptions are enabled.
         *
         * This method logs informational messages when starting the send operation and error messages if the send operation fails.
         * It checks if the client is initialized before attempting to send the request.
         */
        virtual UINT request_send(UINT wait_option);

        /**
         * Retrieves the response body packet from the HTTP client.
         *
         * @param packet_ptr Pointer to store the retrieved packet.
         * @param wait_option Duration to wait for the packet.
         * @return NX_SUCCESS if the packet is retrieved successfully,
         *         NX_NO_PACKET if no packet is available,
         *         NX_WEB_HTTP_GET_DONE if the retrieval process is complete,
         *         or an error code otherwise.
         *
         * Logs informational messages during the process and error messages if the retrieval fails.
         */
        virtual UINT response_body_get(NX_PACKET **packet_ptr, ULONG wait_option);


        using response_header_callback = VOID (*)(NX_WEB_HTTP_CLIENT *client_ptr,
                                                  CHAR *field_name, UINT field_name_length,
                                                  CHAR *field_value, UINT field_value_length);

        /**
         * Registers a callback function to handle response headers.
         *
         * @param callback_function The function to be called when a response header is received.
         * @return NX_SUCCESS if the callback is successfully set, error code otherwise.
         *
         * This method allows the user to specify a custom callback function that will be
         * invoked whenever a response header is processed within the HTTP client. This can
         * be useful for custom monitoring or logging of response headers.
         */
        virtual UINT response_header_callback_set(response_header_callback callback_function);

        /**
         * Connects the BaseClient to the specified server.
         *
         * @param server_ip Pointer to the server's IP address structure.
         * @param server_port The port number of the server to connect to.
         * @param wait_option The duration to wait for the connection to succeed.
         * @return NX_SUCCESS if the connection is successful, error code otherwise.
         * @throws std::runtime_error if connection fails and exceptions are enabled.
         *
         * Establishes a connection to the server using the provided IP address and port.
         * Verifies the validity of the IP address and port before attempting the connection.
         * Checks if the client is ready to connect and retrieves peer information if already connected.
         * Logs informational and error messages during the connection process.
         */
        virtual UINT connect(NXD_ADDRESS *server_ip, UINT server_port, ULONG wait_option);

        using secure_connect_callback = UINT (*)(NX_WEB_HTTP_CLIENT *client_ptr, NX_SECURE_TLS_SESSION *tls);

        /**
         * Establishes a secure connection to a server using the provided parameters.
         *
         * @param server_ip Pointer to the IP address of the server.
         * @param server_port Port number on the server to which the connection is made.
         * @param tls_setup Callback function for configuring TLS settings.
         * @param wait_option Number of ticks to wait for the connection to complete.
         * @return NX_SUCCESS if the connection is successfully established, error code otherwise.
         *
         * Configures and establishes a secure TLS connection to the specified server IP and port.
         * Uses the provided callback to set up TLS parameters and waits for the connection
         * to complete based on the wait_option.
         */
        virtual UINT secure_connect(NXD_ADDRESS *server_ip, UINT server_port,
                                    secure_connect_callback tls_setup, ULONG wait_option);

    protected:
        Stm32ThreadX::EventFlags flags{"Stm32NetXHttpWebClient::Client::flags", getLogger()};

    private:
        Stm32NetX::NetX *nx{};
    };
}
