#include "asiomp.h"
#include "config.h"
#include "socks_session.h"

int main(int argc, char *argv[]) {
    if (!socks_config::get()->parse("../config.yml")) {
        return EXIT_FAILURE;
    }

    session_factory::getInstance()->register_session("socks_session",
        [](asio::ip::tcp::socket socket) -> auto {
        return std::dynamic_pointer_cast<session>(std::make_shared<socks_session>(std::move(socket)));
    });

    if (socks_config::get()->worker_process_num() == 1) {
        asiomp_server(argv, socks_config::get()->address(),
                      socks_config::get()->port(),
                      socks_config::get()->daemon(), "socks_session")
            .run();
    } else {
        asiomp_server(argv, socks_config::get()->address(),
                      socks_config::get()->port(),
                      socks_config::get()->worker_process_num(),
                      socks_config::get()->daemon(), "socks_session")
            .run();
    }

    return EXIT_SUCCESS;
}