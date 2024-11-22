/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#pragma once

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

            char body[256]{};
            snprintf(body, sizeof(body), R"({
"controllerId": "%s",
"secret": "%s",
})", "abc123", "secret");
            const UINT input_size = strlen(body);


            webClient.create();

            Stm32NetX::Packet packet{};
            webClient.packetAllocate(packet);
            packet.dataAppend(body, input_size);


            webClient.requestStart(
                Stm32NetXHttp::Method::POST{},
                "Http://R8.office.easy-smart.cloud/post.php",
                input_size
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
    };
}
