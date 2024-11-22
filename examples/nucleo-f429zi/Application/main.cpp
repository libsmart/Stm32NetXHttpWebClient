/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: AGPL-3.0-only
 */

/**
 * This file holds the main setup() and loop() functions for C++ code.
 * If a RTOS is used, loop() is called in the main task and setup() is called before RTOS initialization.
 * @see App_ThreadX_Init() in Core/Src/app_threadx.c
 */

#include "main.hpp"

#include <Client.hpp>
#include <Stm32NetXHttpWebClient.hpp>

#include "Address.hpp"
#include "eth.h"
#include "globals.hpp"
#include "RunEvery.hpp"
#include "RunOnce.hpp"
#include "RunThreadOnce.hpp"
#include "Stm32NetX.hpp"
#include "Command/RegisterCommands.hpp"
#include "Dns/Dns.hpp"


/**
 * @brief Setup function.
 * This function is called once at the beginning of the program before ThreadX is initialized.
 * @see main() in Core/Src/main.c
 */
void setup() {
    Stm32ItmLogger::logger.setSeverity(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->println("::setup()");

    dummyCpp = 0;
    dummyCandCpp = 0;

    ::AppCore::Command::RegisterCommands()();

    Serial3.begin();
    // print welcome message
    Serial3.print(F("startup "));
    Serial3.print(FIRMWARE_NAME);
    Serial3.print(F(" v"));
    Serial3.print(FIRMWARE_VERSION);
    Serial3.print(F(" "));
    Serial3.println(FIRMWARE_COPY);
    Serial3.flush();
    delay(500);
    Serial3.println(F("OK"));
    Serial3.flush();
}


void loopOnce() {
    Stm32ItmLogger::logger.setSeverity(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->println("::loopOnce()");

#ifdef TX_ENABLE_STACK_CHECKING
    tx_thread_stack_error_notify(Stack_Error_Handler);
#endif

    static char hostname[] = FIRMWARE_NAME"-000000";
    snprintf(hostname, sizeof(hostname), FIRMWARE_NAME"-%02X%02X%02X",
             heth.Init.MACAddr[3], heth.Init.MACAddr[4], heth.Init.MACAddr[5]);
    Stm32NetX::NX->getConfig()->hostname = hostname;
    Stm32NetX::NX->begin();


    // Set up the web client for webAPI
    webClient.setLogger(&Logger);
    webClient.setName("webClient");



}

/**
 * @brief This function is the main loop that executes continuously.
 * The function is called inside the mainLoopThread().
 * @see mainLoopThread() in AZURE_RTOS/App/app_azure_rtos.c
 */
void loop() {
    Serial3.loop();

    static Stm32ThreadX::RunThreadOnce roWebClient;

    if (Stm32NetX::NX->isIpSet()) {
        // Large delay for test ;-)
        roWebClient.loop(UINT32_MAX, []() {
            Stm32ItmLogger::logger.setSeverity(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
                    ->println("::loop() roWebClient");


            Stm32NetX::Address ipAddress;
            ipAddress.nxd_ip_version = NX_IP_VERSION_V4;
            ipAddress.nxd_ip_address.v4 = Stm32NetX::NX->getIpInstance()->ipGatewayAddressGet();
            /*
            dns.setLogger(&Logger);
            dns.setName(Stm32NetX::NX->getConfig()->hostname);
            dns.create();
            dns.serverAdd(&ipAddress);
            dns.hostByNameGet((CHAR *) "easy-smart.ch", &ipAddress, TX_TIMER_TICKS_PER_SECOND, NX_IP_VERSION_V4);
            */

            Logger.printf("IP_ADDRESS: %lu.%lu.%lu.%lu\r\n",
                          (ipAddress.nxd_ip_address.v4 >> 24) & 0xff,
                          (ipAddress.nxd_ip_address.v4 >> 16) & 0xff,
                          (ipAddress.nxd_ip_address.v4 >> 8) & 0xff,
                          (ipAddress.nxd_ip_address.v4 >> 0) & 0xff
            );


            // webClient.setLogger(&Logger);
            // webClient.setName("webClient");
            webClient.create();

            // ipAddress.nxd_ip_version = NX_IP_VERSION_V4;
            // ipAddress.nxd_ip_address.v4 = IP_ADDRESS(10, 82, 2, 198);
            UINT ret=NX_SUCCESS;
            // auto ret = webClient.getSecureStart(&ipAddress, NX_WEB_HTTP_SERVER_PORT, (char *) "/",
                                                // (CHAR *) "easy-smart.ch",
                                                // NX_NULL, NX_NULL, TX_TIMER_TICKS_PER_SECOND);
            if (ret == NX_SUCCESS) {
                NX_PACKET *packet = nullptr;
                do {
                    ret = webClient.responseBodyGet(&packet, TX_TIMER_TICKS_PER_SECOND);
                    if (packet != NX_NULL) {
                        char buffer[2048];
                        ULONG bytes_copied{};
                        auto ret2 = nx_packet_data_retrieve(packet, buffer, &bytes_copied);
                        if (ret2 != NX_SUCCESS) {
                            Logger.printf("nx_packet_data_retrieve() = 0x%02x\r\n", ret2);
                        }


                        Serial3.printf("Received %lu bytes\r\n", bytes_copied);
                        Serial3.printf("%.*s", bytes_copied, buffer);
                        Serial3.println();
                        Serial3.println();

                        nx_packet_release(packet);
                    }
                } while (ret != NX_WEB_HTTP_GET_DONE && ret != NX_WEB_HTTP_ERROR);
            }
        });
    }

    static Stm32Common::RunEvery re1(3000);
    re1.loop([]() {
        // telnetServer.broadcast()->printf("counter = %d\r\n", dummyCpp);
    });

    static Stm32Common::RunEvery re2(300);
    re2.loop([]() {
        HAL_GPIO_WritePin(LD1_GPIO_Port, LD1_Pin, dummyCpp & 1 ? GPIO_PIN_RESET : GPIO_PIN_SET);
        HAL_GPIO_WritePin(LD2_GPIO_Port, LD2_Pin, dummyCpp & 2 ? GPIO_PIN_RESET : GPIO_PIN_SET);
        HAL_GPIO_WritePin(LD3_GPIO_Port, LD3_Pin, dummyCpp & 4 ? GPIO_PIN_RESET : GPIO_PIN_SET);
        // Logger.printf("counter = %d\r\n", dummyCpp);
        dummyCpp++;
        dummyCandCpp++;
    });
}


/**
 * @brief This function handles fatal errors.
 * @see Error_Handler() in Core/Src/main.c
 */
[[noreturn]] void errorHandler() {
    HAL_GPIO_WritePin(LD1_GPIO_Port, LD1_Pin, GPIO_PIN_RESET);
    HAL_GPIO_WritePin(LD2_GPIO_Port, LD2_Pin, GPIO_PIN_RESET);
    HAL_GPIO_WritePin(LD3_GPIO_Port, LD3_Pin, GPIO_PIN_RESET);

    while (true) {
        for (uint32_t i = (SystemCoreClock / 10); i > 0; i--) { UNUSED(i); }
        HAL_GPIO_TogglePin(LD1_GPIO_Port, LD1_Pin);
        HAL_GPIO_TogglePin(LD2_GPIO_Port, LD2_Pin);
        HAL_GPIO_TogglePin(LD3_GPIO_Port, LD3_Pin);
    }
}


[[noreturn]] void Stack_Error_Handler(TX_THREAD *thread_ptr) {
    Logger.print("==> Stack_Error_Handler() called in thread ");
    Logger.println(thread_ptr->tx_thread_name);
    Logger.print("    Stack size: ");
    Logger.println(thread_ptr->tx_thread_stack_size);
    Error_Handler();
    __disable_irq();
    for (;;) { ; }
}
