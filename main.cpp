#include "asiomp.h"

int main(int argc, char *argv[]) {
    if (!socks_config::get()->parse("../config.yml")) {
        return EXIT_FAILURE;
    }

    if (socks_config::get()->worker_process_num() == 1) {
        asiomp_server(argv, socks_config::get()->address(),
                      socks_config::get()->port())
            .run();
    } else {
        asiomp_server(argv, socks_config::get()->address(),
                      socks_config::get()->port(),
                      socks_config::get()->worker_process_num())
            .run();
    }

    return EXIT_SUCCESS;
}