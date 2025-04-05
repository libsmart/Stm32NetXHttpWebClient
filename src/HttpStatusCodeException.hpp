/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once
#include <cstdint>
#include <exception>
#include <optional>
#include <variant>

#include "nx_web_http_common.h"

namespace Stm32NetXHttpCommon {
    class HttpStatusCode {
    public:
        /** HTTP status code unknown */
        struct NONE {
            static constexpr char name[] = "NONE";
            explicit operator const char *() const { return name; }
            static constexpr int16_t getCode() { return INT16_MAX; }
            static constexpr UINT nxWebReturnCode() { return UINT_MAX; }
        };

        /** HTTP status code 100 Continue */
        struct CONTINUE {
            static constexpr char name[] = "CONTINUE";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 100; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_CONTINUE; }
        };

        /** HTTP status code 101 Switching Protocols */
        struct SWITCHING_PROTOCOLS {
            static constexpr char name[] = "SWITCHING_PROTOCOLS";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 101; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_SWITCHING_PROTOCOLS; }
        };

        /** HTTP status code 201 Created */
        struct CREATED {
            static constexpr char name[] = "CREATED";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 201; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_CREATED; }
        };

        /** HTTP status code 202 Accepted */
        struct ACCEPTED {
            static constexpr char name[] = "ACCEPTED";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 202; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_ACCEPTED; }
        };

        /** HTTP status code 203 Non-Authoritative Information */
        struct NON_AUTH_INFO {
            static constexpr char name[] = "NON_AUTH_INFO";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 203; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_NON_AUTH_INFO; }
        };

        /** HTTP status code 204 No Content */
        struct NO_CONTENT {
            static constexpr char name[] = "NO_CONTENT";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 204; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_NO_CONTENT; }
        };

        /** HTTP status code 205 Reset Content */
        struct RESET_CONTENT {
            static constexpr char name[] = "RESET_CONTENT";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 205; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_RESET_CONTENT; }
        };

        /** HTTP status code 206 Partial Content */
        struct PARTIAL_CONTENT {
            static constexpr char name[] = "PARTIAL_CONTENT";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 206; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_PARTIAL_CONTENT; }
        };

        /** HTTP status code 300 Multiple Choices */
        struct MULTIPLE_CHOICES {
            static constexpr char name[] = "MULTIPLE_CHOICES";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 300; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_MULTIPLE_CHOICES; }
        };

        /** HTTP status code 301 Moved Permanently */
        struct MOVED_PERMANENTLY {
            static constexpr char name[] = "MOVED_PERMANENTLY";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 301; }

            static constexpr UINT nxWebReturnCode() {
                return NX_WEB_HTTP_STATUS_CODE_MOVED_PERMANETLY; /* sic */
            }
        };

        /** HTTP status code 302 Found */
        struct FOUND {
            static constexpr char name[] = "FOUND";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 302; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_FOUND; }
        };

        /** HTTP status code 303 See Other */
        struct SEE_OTHER {
            static constexpr char name[] = "SEE_OTHER";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 303; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_SEE_OTHER; }
        };

        /** HTTP status code 304 Not Modified */
        struct NOT_MODIFIED {
            static constexpr char name[] = "NOT_MODIFIED";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 304; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_NOT_MODIFIED; }
        };

        /** HTTP status code 305 Use Proxy */
        struct USE_PROXY {
            static constexpr char name[] = "USE_PROXY";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 305; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_USE_PROXY; }
        };

        /** HTTP status code 307 Temporary Redirect */
        struct TEMPORARY_REDIRECT {
            static constexpr char name[] = "TEMPORARY_REDIRECT";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 307; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_TEMPORARY_REDIRECT; }
        };

        /** HTTP status code 400 Bad Request */
        struct BAD_REQUEST {
            static constexpr char name[] = "BAD_REQUEST";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 400; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_BAD_REQUEST; }
        };

        /** HTTP status code 401 Unauthorized */
        struct UNAUTHORIZED {
            static constexpr char name[] = "UNAUTHORIZED";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 401; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_UNAUTHORIZED; }
        };

        /** HTTP status code 402 Payment Required */
        struct PAYMENT_REQUIRED {
            static constexpr char name[] = "PAYMENT_REQUIRED";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 402; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_PAYMENT_REQUIRED; }
        };

        /** HTTP status code 403 Forbidden */
        struct FORBIDDEN {
            static constexpr char name[] = "FORBIDDEN";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 403; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_FORBIDDEN; }
        };

        /** HTTP status code 404 Not Found */
        struct NOT_FOUND {
            static constexpr char name[] = "NOT_FOUND";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 404; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_NOT_FOUND; }
        };

        /** HTTP status code 405 Method Not Allowed */
        struct METHOD_NOT_ALLOWED {
            static constexpr char name[] = "METHOD_NOT_ALLOWED";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 405; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_METHOD_NOT_ALLOWED; }
        };

        /** HTTP status code 406 Not Acceptable */
        struct NOT_ACCEPTABLE {
            static constexpr char name[] = "NOT_ACCEPTABLE";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 406; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_NOT_ACCEPTABLE; }
        };

        /** HTTP status code 407 Proxy Authentication Required */
        struct PROXY_AUTH_REQUIRED {
            static constexpr char name[] = "PROXY_AUTH_REQUIRED";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 407; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_PROXY_AUTH_REQUIRED; }
        };

        /** HTTP status code 408 Request Time-out */
        struct REQUEST_TIMEOUT {
            static constexpr char name[] = "REQUEST_TIMEOUT";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 408; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_REQUEST_TIMEOUT; }
        };

        /** HTTP status code 409 Conflict */
        struct CONFLICT {
            static constexpr char name[] = "CONFLICT";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 409; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_CONFLICT; }
        };

        /** HTTP status code 410 Gone */
        struct GONE {
            static constexpr char name[] = "GONE";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 410; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_GONE; }
        };

        /** HTTP status code 411 Length Required */
        struct LENGTH_REQUIRED {
            static constexpr char name[] = "LENGTH_REQUIRED";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 411; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_LENGTH_REQUIRED; }
        };

        /** HTTP status code 412 Precondition Failed */
        struct PRECONDITION_FAILED {
            static constexpr char name[] = "PRECONDITION_FAILED";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 412; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_PRECONDITION_FAILED; }
        };

        /** HTTP status code 413 Request Entity Too Large */
        struct ENTITY_TOO_LARGE {
            static constexpr char name[] = "ENTITY_TOO_LARGE";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 413; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_ENTITY_TOO_LARGE; }
        };

        /** HTTP status code 414 Request URL Too Large */
        struct URL_TOO_LARGE {
            static constexpr char name[] = "URL_TOO_LARGE";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 414; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_URL_TOO_LARGE; }
        };

        /** HTTP status code 415 Unsupported Media Type */
        struct UNSUPPORTED_MEDIA {
            static constexpr char name[] = "UNSUPPORTED_MEDIA";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 415; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_UNSUPPORTED_MEDIA; }
        };

        /** HTTP status code 416 Requested range not satisfiable */
        struct RANGE_NOT_SATISFY {
            static constexpr char name[] = "RANGE_NOT_SATISFY";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 416; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_RANGE_NOT_SATISFY; }
        };

        /** HTTP status code 417 Expectation Failed */
        struct EXPECTATION_FAILED {
            static constexpr char name[] = "EXPECTATION_FAILED";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 417; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_EXPECTATION_FAILED; }
        };

        /** HTTP status code 500 Internal Server Error */
        struct INTERNAL_ERROR {
            static constexpr char name[] = "INTERNAL_ERROR";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 500; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_INTERNAL_ERROR; }
        };

        /** HTTP status code 501 Not Implemented */
        struct NOT_IMPLEMENTED {
            static constexpr char name[] = "NOT_IMPLEMENTED";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 501; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_NOT_IMPLEMENTED; }
        };

        /** HTTP status code 502 Bad Gateway */
        struct BAD_GATEWAY {
            static constexpr char name[] = "BAD_GATEWAY";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 502; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_BAD_GATEWAY; }
        };

        /** HTTP status code 503 Service Unavailable */
        struct SERVICE_UNAVAILABLE {
            static constexpr char name[] = "SERVICE_UNAVAILABLE";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 503; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_SERVICE_UNAVAILABLE; }
        };

        /** HTTP status code 504 Gateway Time-out */
        struct GATEWAY_TIMEOUT {
            static constexpr char name[] = "GATEWAY_TIMEOUT";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 504; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_GATEWAY_TIMEOUT; }
        };

        /** HTTP status code 505 HTTP Version not supported */
        struct VERSION_ERROR {
            static constexpr char name[] = "GATEWAY_TIMEOUT";
            explicit operator const char *() const { return name; }
            static constexpr uint16_t getCode() { return 505; }
            static constexpr UINT nxWebReturnCode() { return NX_WEB_HTTP_STATUS_CODE_VERSION_ERROR; }
        };

        using Variant = std::variant<
            NONE,
            CONTINUE,
            SWITCHING_PROTOCOLS,
            CREATED,
            ACCEPTED,
            NON_AUTH_INFO,
            NO_CONTENT,
            RESET_CONTENT,
            PARTIAL_CONTENT,
            MULTIPLE_CHOICES,
            MOVED_PERMANENTLY,
            FOUND,
            SEE_OTHER,
            NOT_MODIFIED,
            USE_PROXY,
            TEMPORARY_REDIRECT,
            BAD_REQUEST,
            UNAUTHORIZED,
            PAYMENT_REQUIRED,
            FORBIDDEN,
            NOT_FOUND,
            METHOD_NOT_ALLOWED,
            NOT_ACCEPTABLE,
            PROXY_AUTH_REQUIRED,
            REQUEST_TIMEOUT,
            CONFLICT,
            GONE,
            LENGTH_REQUIRED,
            PRECONDITION_FAILED,
            ENTITY_TOO_LARGE,
            URL_TOO_LARGE,
            UNSUPPORTED_MEDIA,
            RANGE_NOT_SATISFY,
            EXPECTATION_FAILED,
            INTERNAL_ERROR,
            NOT_IMPLEMENTED,
            BAD_GATEWAY,
            SERVICE_UNAVAILABLE,
            GATEWAY_TIMEOUT,
            VERSION_ERROR
        >;

        // Eigene Implementierung von 'type_identity' für C++17
        template<typename T>
        struct type_identity {
            using type = T;
        };

        // Hilfsfunktion: Schleife über alle Typen der `Variant`
        template<typename Func, size_t... Is>
        static void forEachTypeImpl(Func &&func, std::index_sequence<Is...>) {
            using VariantType = Variant;
            (..., func(type_identity<std::variant_alternative_t<Is, VariantType> >{}));
        }

        template<typename Func>
        static void forEachType(Func &&func) {
            constexpr size_t VariantSize = std::variant_size<Variant>::value;
            forEachTypeImpl(std::forward<Func>(func), std::make_index_sequence<VariantSize>{});
        }

        static auto find(uint32_t subject) -> std::optional<Variant> {
            std::optional<Variant> result;

            forEachType(
                [&subject, &result](auto type_info) {
                    using T = typename decltype(type_info)::type; // Laufender Typ aus der Variante
                    T instance;

                    // Vergleiche
                    if (instance.getCode() == subject || instance.nxWebReturnCode() == subject) {
                        result = instance; // Speichere das Ergebnis
                    }
                });

            return result;
        }
    };

    class HttpStatusCodeException : public std::exception {
    public:
        HttpStatusCodeException() = delete;

        explicit HttpStatusCodeException(const uint16_t statusCodeNum)
            : HttpStatusCodeException(
                HttpStatusCode::find(statusCodeNum).value_or(HttpStatusCode::NONE{})
            ) { ; }

        explicit HttpStatusCodeException(const HttpStatusCode::Variant &statusCode)
            : statusCode(statusCode) { ; }

        [[nodiscard]] const char *what() const noexcept override {
            auto i = std::visit(
                [this](auto value) {
                    // return value;
                    using T = std::decay_t<decltype(value)>;
                    return T::name;
                },
                statusCode);
            return i;
        }

    private:
        HttpStatusCode::Variant statusCode;
    };
}
