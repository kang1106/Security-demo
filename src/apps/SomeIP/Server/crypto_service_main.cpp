// Copyright (C) 2015-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
#ifndef VSOMEIP_ENABLE_SIGNAL_HANDLING
#include <csignal>
#endif
#include <vsomeip/vsomeip.hpp>
#include "crypto_service.hpp"

#ifndef VSOMEIP_ENABLE_SIGNAL_HANDLING
crypto_service *crypto_srv_ptr(nullptr);
    void handle_signal(int _signal) {
        if (crypto_srv_ptr != nullptr &&
                (_signal == SIGINT || _signal == SIGTERM))
            crypto_srv_ptr->terminate();
    }
#endif

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    crypto_service crypto_srv;
#ifndef VSOMEIP_ENABLE_SIGNAL_HANDLING
    crypto_srv_ptr = &crypto_srv;
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
#endif
    if (crypto_srv.init()) {
        crypto_srv.start();
        return 0;
    } else {
        return 1;
    }
}
