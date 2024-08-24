/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: AGPL-3.0-only
 */

/**
 * This file holds exports for the global variables, defined in globals.cpp.
 * @see globals.cpp
 */

#ifndef NUCLEO_F429ZI_APPLICATION_GLOBALS_HPP
#define NUCLEO_F429ZI_APPLICATION_GLOBALS_HPP

#include "globals.h"
#include "Stm32ItmLogger.hpp"
#include <cstdint>
#include "Driver/Stm32HalUartItDriver.hpp"

#ifdef __cplusplus
extern "C" {
#endif

extern uint32_t dummyCpp;

/**
 * Global logger instance
 */
inline Stm32ItmLogger::Stm32ItmLogger &Logger = Stm32ItmLogger::logger;

inline Stm32Serial::Stm32HalUartItDriver uart3Driver(&huart3, "uart3Driver");
inline Stm32Serial::Stm32Serial Serial3(&uart3Driver);


#ifdef __cplusplus
}
#endif

#endif
