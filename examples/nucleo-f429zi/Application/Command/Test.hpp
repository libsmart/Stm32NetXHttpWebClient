/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#pragma once

#include <lwjson/lwjson.h>

#include "globals.hpp"
#include "Command/AbstractCommand.hpp"
#include "ezShell/Shell.hpp"
#include "Packet/Packet.hpp"

namespace AppCore::Command {
    class Test : public Stm32Shell::Command::AbstractCommand {
    public:
        Test() {
            Nameable::setName("test");
            isSync = true;
            setLogger(&Logger);
        }

        runReturn run() override {
            auto ret = AbstractCommand::run();

            try {
                if (std::strcmp(argv[1], "timestamp") == 0) {
                    ret = runTimestamp();
                }

                if (std::strcmp(argv[1], "post") == 0) {
                    ret = runPost();
                }

                if (std::strcmp(argv[1], "time") == 0) {
                    ret = runTime();
                }
            } catch (const std::exception &e) {
                ret = runReturn::ERROR;
                log()->setSeverity(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                        ->printf("ERROR: %s\r\n", e.what());
                out()->printf("ERROR: %s\r\n", e.what());
            }

            if (ret == runReturn::ERROR) {
                webClient.del();
            }

            return ret;
        }

    private:
        runReturn runTimestamp() {
            Stm32ItmLogger::logger.setSeverity(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
                    ->println("Test::runTimestamp()");

            UINT ret = NX_SUCCESS;


            /*
                        Stm32NetX::Address ipAddress{10, 82, 2, 198};

                        ret = webClient.create();
                        if(ret != NX_SUCCESS) {
                            return runReturn::ERROR;
                        }

                        ret = webClient.connect(&ipAddress, 80, NX_WAIT_FOREVER);
                        if(ret != NX_SUCCESS) {
                            return runReturn::ERROR;
                        }

                        Stm32NetXHttpWebClient::Request *req = webClient.initializeRequest(
                            Stm32NetXHttp::Method::GET{}, "http://10.82.2.198:80/timestamp.php");
                        if(req == nullptr) {
                            return runReturn::ERROR;
                        }
            */

            webClient.requestStart(
                Stm32NetXHttp::Method::GET{}, "Http://R8.office.easy-smart.cloud/timestamp.php"
            );
            // Stm32NetXHttpWebClient::Request *req = webClient.requestStart(
            // Stm32NetXHttp::Method::GET{}, "http://R8.office.easy-smart.cloud/timestamp.php"
            // );
            // Stm32NetXHttpWebClient::Request *req = webClient.requestStart(
            // Stm32NetXHttp::Method::GET{}, "http://R8.office.easy-smart.cloud:80/timestamp.php"
            // );
            // Stm32NetXHttpWebClient::Request *req = webClient.requestStart(
            // Stm32NetXHttp::Method::GET{}, "http://10.82.2.198:80/timestamp.php"
            // );


            ret = webClient.headerAdd("Connection", "keep-alive");
            if (ret != NX_SUCCESS) {
                return runReturn::ERROR;
            }

            // ret = req->headerAdd("Content-Type", "application/json");
            // if(ret != NX_SUCCESS) {
            //     return runReturn::ERROR;
            // }

            // ret = req->headerAdd("Content-Length", "0");
            // if(ret != NX_SUCCESS) {
            //     return runReturn::ERROR;
            // }

            // ret = req->headerAdd("Accept", "application/json");
            // if(ret != NX_SUCCESS) {
            //     return runReturn::ERROR;
            // }

            ret = webClient.headerAdd("Accept-Encoding", "identity;q=1.0, *;q=0");
            if (ret != NX_SUCCESS) {
                return runReturn::ERROR;
            }


            ret = webClient.send();
            if (ret != NX_SUCCESS) {
                return runReturn::ERROR;
            }


            // Paket für den Body allozieren und füllen
            NX_PACKET *packet{nullptr};
            // req->packetAllocate(&packet, NX_WAIT_FOREVER);


            packet = nullptr;
            do {
                ret = webClient.responseBodyGet(&packet, TX_TIMER_TICKS_PER_SECOND);
                if (packet != NX_NULL) {
                    char buffer[2048];
                    ULONG bytes_copied{};
                    auto ret2 = nx_packet_data_retrieve(packet, buffer, &bytes_copied);
                    if (ret2 != NX_SUCCESS) {
                        log()->printf("nx_packet_data_retrieve() = 0x%02x\r\n", ret2);
                    }


                    log()->printf("Received %lu bytes\r\n", bytes_copied);
                    log()->printf("%.*s", bytes_copied, buffer);
                    log()->println();
                    log()->println();
                    out()->printf("%.*s", bytes_copied, buffer);
                    out()->println();

                    nx_packet_release(packet);
                }
            } while (ret != NX_WEB_HTTP_GET_DONE && ret != NX_WEB_HTTP_ERROR);

            if (ret == NX_WEB_HTTP_GET_DONE) {
                webClient.isConnected();
                return runReturn::FINISHED;
            }

            return runReturn::ERROR;
        }


        runReturn runPost() {
            UINT ret = NX_SUCCESS;

            // char body[256]{};
            //             snprintf(body, sizeof(body), R"({
            // "controllerId": "%s",
            // "secret": "%s",
            // })", "abc123", "secret");
            // const UINT input_size = strlen(body);


            webClient.create();

            Stm32NetX::Packet packet{};
            webClient.packetAllocate(packet);
            // packet.dataAppend(body, input_size);


            log()->printf("packet.lengthGet() = %lu | packet.availableForWrite() = %lu\r\n",
                          packet.lengthGet(), packet.availableForWrite());


            packet.printf(R"({
"controllerId": "%s",
"secret": "%s",
})", "abc123", "secret");

            log()->printf("packet.lengthGet() = %lu | packet.availableForWrite() = %lu\r\n",
                          packet.lengthGet(), packet.availableForWrite());


            webClient.requestStart(
                Stm32NetXHttp::Method::POST{},
                "Http://R8.office.easy-smart.cloud/post.php",
                packet.lengthGet()
            );

            webClient.headerAdd("Accept-Encoding", "identity;q=1.0, *;q=0");
            webClient.headerAdd("Content-Type", "application/json");

            webClient.send();
            webClient.packetSend(&packet);

            /*
            Stm32NetX::Packet packet{};
            req->packetAllocate(packet);

            ret = packet.dataAppend(body, input_size);
            if (ret != NX_SUCCESS) {
                return runReturn::ERROR;
            }

            req->packetSend(&packet);
            */


            packet = nullptr;
            // NX_PACKET *pkt{nullptr};
            do {
                ret = webClient.responseBodyGet(packet);
                if (packet.getNxPacket() != NX_NULL) {
                    char buffer[2048];
                    ULONG bytes_copied{};
                    packet.data_retrieve(buffer, &bytes_copied);

                    log()->printf("Received %lu bytes\r\n", bytes_copied);
                    log()->printf("%.*s", bytes_copied, buffer);
                    log()->println();
                    log()->println();
                    out()->printf("%.*s", bytes_copied, buffer);
                    out()->println();

                    packet.release();
                }
            } while (ret != NX_WEB_HTTP_GET_DONE && ret != NX_WEB_HTTP_ERROR);

            if (ret == NX_WEB_HTTP_GET_DONE) {
                webClient.isConnected();
                return runReturn::FINISHED;
            }

            return runReturn::ERROR;
        }


        runReturn runTime() {
            UINT ret = NX_SUCCESS;

            webClient.create();

            webClient.requestStart(
                Stm32NetXHttp::Method::GET{},
                "Http://R8.office.easy-smart.cloud/terminal/info.php"
            );

            webClient.headerAdd("Accept-Encoding", "identity;q=1.0, *;q=0");

            webClient.send();

            Stm32NetX::Packet packet{};

            packet = nullptr;
            // NX_PACKET *pkt{nullptr};
            do {
                ret = webClient.responseBodyGet(packet);
                if (packet.getNxPacket() != NX_NULL) {
                    char buffer[2048]{};
                    ULONG bytes_copied{};
                    packet.data_retrieve(buffer, &bytes_copied);

                    log()->printf("Received %lu bytes\r\n", bytes_copied);
                    log()->printf("%.*s", bytes_copied, buffer);
                    log()->println();
                    log()->println();
                    out()->printf("%.*s", bytes_copied, buffer);
                    out()->println();


                    /* LwJSON instance and tokens */
                    static lwjson_token_t tokens[128];
                    static lwjson_t lwjson;

                    lwjson_init(&lwjson, tokens, LWJSON_ARRAYSIZE(tokens));
                    if (lwjson_parse(&lwjson, buffer) == lwjsonOK) {
                        const lwjson_token_t *tSuccessful{};
                        const lwjson_token_t *t{};
                        log()->printf("JSON parsed..\r\n");

                        /* Find key "successful" in JSON */
                        if ((tSuccessful = lwjson_find(&lwjson, "successful")) != NULL) {
                            log()->printf("Key found with data type: %d\r\n", (int) tSuccessful->type);
                        }

                        if (tSuccessful->type == LWJSON_TYPE_TRUE) {
                            /* Find key "serverTime" in JSON */
                            if ((t = lwjson_find(&lwjson, "resultObject.info.serverTime")) != NULL) {
                                log()->printf("Key found with data type: %d\r\n", (int) t->type);
                                if (t->type == LWJSON_TYPE_STRING) {
                                    size_t datetimestring_len = 0;
                                    const char *datetimestring = lwjson_get_val_string(t, &datetimestring_len);
                                    out()->printf("Server time: %.*s\r\n", static_cast<int>(datetimestring_len),
                                                  datetimestring);
                                }
                            }

                            /* Find key "chronoVersion" in JSON */
                            if ((t = lwjson_find(&lwjson, "resultObject.info.chronoVersion")) != NULL) {
                                log()->printf("Key found with data type: %d\r\n", (int) t->type);
                                if (t->type == LWJSON_TYPE_NUM_INT) {
                                    const int chronoversion = lwjson_get_val_int(t);
                                    out()->printf("Chrono version: %d\r\n", chronoversion);
                                }
                            }
                        }

                        delay(100);

                        /* Call this when not used anymore */
                        lwjson_free(&lwjson);
                    }

                    packet.release();
                }
            } while (ret != NX_WEB_HTTP_GET_DONE && ret != NX_WEB_HTTP_ERROR);

            if (ret == NX_WEB_HTTP_GET_DONE) {
                webClient.isConnected();
                return runReturn::FINISHED;
            }

            return runReturn::ERROR;
        }
    };
}
