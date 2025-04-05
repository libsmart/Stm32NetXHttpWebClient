/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once
#include <stdexcept>

namespace Stm32NetXHttpWebClient {
    class TimeoutException final : public std::runtime_error {
    public:
        TimeoutException() : TimeoutException("Timeout") { ; }

        explicit TimeoutException(const char *string)
            : runtime_error(string) { ; }
    };
}
