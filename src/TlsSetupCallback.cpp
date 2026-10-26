/*
 * SPDX-FileCopyrightText: 2026 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "TlsSetupCallback.hpp"
#include "Client.hpp"
#include "Helper.hpp"

Stm32NetXHttpWebClient::TlsSetupCallback::TlsSetupCallback(Client &client): webClient(client) {
    setLogger(webClient.getLogger());
    client.registerTlsSetupCallback(this);
}

UINT Stm32NetXHttpWebClient::TlsSetupCallback::tlsSetupCallback(NX_SECURE_TLS_SESSION_STRUCT *tls_session) {

    UINT ret;

    // Initialize TLS module
    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-secure-tls/chapter4.md#nx_secure_tls_initialize
    nx_secure_tls_initialize();


    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-secure-tls/chapter4.md#nx_secure_tls_metadata_size_calculate
    ULONG metadata_size=0;
    ret = nx_secure_tls_metadata_size_calculate(&nx_crypto_tls_ciphers_ecc, &metadata_size);
    if (ret != NX_SUCCESS) {
        constexpr char fmt[] = "Stm32NetXHttpWebClient::tlsSetupCallback[%s]: nx_secure_tls_metadata_size_calculate() = 0x%02x";
        LIBSMART_HANDLE_ERROR(fmt, webClient.getName(), ret);
        return ret;
    }

    if (metadata_size > sizeof(crypto_metadata)) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf("metadata_size = %lu  >  sizeof(crypto_metadata) = %lu\r\n", metadata_size,
                         sizeof(crypto_metadata));
    }


    // Create a TLS session
    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-secure-tls/chapter4.md#nx_secure_tls_session_create
    ret = nx_secure_tls_session_create(tls_session, &nx_crypto_tls_ciphers_ecc,
                                       crypto_metadata, sizeof(crypto_metadata));
    if (ret != NX_SUCCESS) {
        constexpr char fmt[] = "Stm32NetXHttpWebClient::tlsSetupCallback[%s]: nx_secure_tls_session_create() = 0x%02x";
        LIBSMART_HANDLE_ERROR(fmt, webClient.getName(), ret);
        return ret;
    }


    // Set host name for SNI
    ret = nx_secure_tls_session_sni_extension_set(tls_session, &dns_name);
    if (ret != NX_SUCCESS) {
        constexpr char fmt[] = "Stm32NetXHttpWebClient::TlsSetupCallback[%s]: nx_secure_tls_session_sni_extension_set() = 0x%02x";
        LIBSMART_HANDLE_ERROR(fmt, webClient.getName(), ret);
        return ret;
    }






    // Allocate space for packet reassembly
    ret = nx_secure_tls_session_packet_buffer_set(tls_session, tls_packet_buffer,
                                                  sizeof(tls_packet_buffer));
    if (ret != NX_SUCCESS) {
        constexpr char fmt[] = "Stm32NetXHttpWebClient::tlsSetupCallback[%s]: nx_secure_tls_session_packet_buffer_set() = 0x%02x";
        LIBSMART_HANDLE_ERROR(fmt, webClient.getName(), ret);
        return ret;
    }


    // Need to allocate space for the certificate coming in from the broker
    memset(&remote_certificate, 0, sizeof(NX_SECURE_X509_CERT));

    // allocate space for the certificate coming in from the remote host
    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-secure-tls/chapter4.md#nx_secure_tls_remote_certificate_allocate
    ret = nx_secure_tls_remote_certificate_allocate(tls_session, &remote_certificate,
                                                    remote_cert_buffer, sizeof(remote_cert_buffer));
    if (ret != NX_SUCCESS) {
        constexpr char fmt[] = "Stm32NetXHttpWebClient::tlsSetupCallback[%s]: nx_secure_tls_remote_certificate_allocate() = 0x%02x";
        LIBSMART_HANDLE_ERROR(fmt, webClient.getName(), ret);
        return ret;
    }

    // Add a CA Certificate to our trusted store for verifying incoming server certificates
    // nx_secure_x509_certificate_initialize(&trusted_certificate, trusted_cert_der,
    // trusted_cert_der_len, NX_NULL, 0, NULL, 0,
    // NX_SECURE_X509_KEY_TYPE_NONE);
    // nx_secure_tls_trusted_certificate_add(tls_session, &trusted_certificate);

    // Need to allocate space for the certificate coming in from the remote host
    // nx_secure_tls_remote_certificate_allocate(tls_session, &remote_certificate,
    // remote_cert_buffer, sizeof(remote_cert_buffer));
    // nx_secure_tls_remote_certificate_allocate(tls_session, &remote_issuer,
    // remote_issuer_buffer, sizeof(remote_issuer_buffer));

    return NX_SUCCESS;


    return NX_NOT_IMPLEMENTED;
}

Stm32NetXHttpWebClient::Client & Stm32NetXHttpWebClient::TlsSetupCallback::getWebClient() const {
    return webClient;
}

UINT Stm32NetXHttpWebClient::TlsSetupCallback::callback(NX_WEB_HTTP_CLIENT_STRUCT *clt,
                                                        NX_SECURE_TLS_SESSION_STRUCT *tls_session) {

    Stm32ItmLogger::logger.setSeverity(Stm32ItmLogger::LoggerInterface::Severity::WARNING);
    Stm32ItmLogger::logger.println("Stm32NetXHttpWebClient::TlsSetupCallback::callback()");

    return tlsSetupCallback(tls_session);
}
