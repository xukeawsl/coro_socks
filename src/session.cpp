#include "session.h"

session::session(asio::ip::tcp::socket socket)
    : socket_(std::move(socket)),
      keep_alive_time_(socks_config::get()->keep_alive_time()),
      keep_alive_timer_(socket_.get_executor()),
      tcp_dst_socket_(socket_.get_executor()) {
    this->keep_alive_timer_.expires_at(
        std::chrono::steady_clock::time_point::max());
}

session::~session() {}

void session::start() {
    this->flush_deadline();

    asio::co_spawn(
        this->socket_.get_executor(),
        [self = shared_from_this()] { return self->handle_packet(); },
        asio::detached);

    asio::co_spawn(
        this->socket_.get_executor(),
        [self = shared_from_this()] { return self->handle_keep_alive(); },
        asio::detached);
}

void session::flush_deadline() {
    this->deadline_ = std::chrono::steady_clock::now() +
                      std::chrono::seconds(this->keep_alive_time_);
}

void session::stop() {
    asio::error_code ignored_ec;
    this->socket_.close(ignored_ec);
    this->keep_alive_timer_.cancel(ignored_ec);
    this->tcp_dst_socket_.close(ignored_ec);
}

asio::awaitable<void> session::handle_keep_alive() {
    auto check_duration =
        std::chrono::seconds(socks_config::get()->check_duration());

    while (this->socket_.is_open()) {
        this->keep_alive_timer_.expires_after(check_duration);

        co_await this->keep_alive_timer_.async_wait(asio::use_awaitable);

        if (this->deadline_ <= std::chrono::steady_clock::now()) {
            this->stop();
        }
    }

    co_return;
}

asio::awaitable<void> session::handle_packet() {
    bool ret;
    uint8_t ver;
    uint8_t nmethods;
    std::string methods;
    uint8_t choose_method;

    ret = co_await this->read_byte(&ver);
    if (!ret) {
        this->stop();
        co_return;
    }

    if (ver != coro_socks::Version::V5) {
        this->stop();
        co_return;
    }

    ret = co_await this->read_byte(&nmethods);
    if (!ret) {
        this->stop();
        co_return;
    }

    ret = co_await this->read_bytes_n(methods, nmethods);
    if (!ret) {
        this->stop();
        co_return;
    }

    choose_method = coro_socks::Method::NoAcceptable;

    for (uint8_t method : methods) {
        if (method == coro_socks::Method::NoAuth &&
            !socks_config::get()->auth()) {
            choose_method = method;
        } else if (method == coro_socks::Method::UserPassWd &&
                   socks_config::get()->auth()) {
            choose_method = method;
        }
    }

    std::array<asio::const_buffer, 2> buf = {
        {asio::buffer(&ver, 1), asio::buffer(&choose_method, 1)}};

    asio::error_code ec;
    co_await asio::async_write(this->socket_, buf,
                               asio::redirect_error(asio::use_awaitable, ec));
    if (ec) {
        this->stop();
        co_return;
    }

    switch (choose_method) {
        case coro_socks::Method::NoAuth: {
            co_await this->handle_client_request();
            break;
        }
        case coro_socks::Method::UserPassWd: {
            co_await this->handle_authentication();
            break;
        }
    }

    co_return;
}

asio::awaitable<void> session::handle_authentication() {
    bool ret;
    uint8_t ver;
    uint8_t ulen;
    std::string uname;
    uint8_t plen;
    std::string passwd;
    uint8_t status;

    ret = co_await this->read_byte(&ver);
    if (!ret) {
        this->stop();
        co_return;
    }

    if (ver != coro_socks::Version::V5) {
        this->stop();
        co_return;
    }

    ret = co_await this->read_byte(&ulen);
    if (!ret) {
        this->stop();
        co_return;
    }

    if (ulen == 0) {
        this->stop();
        co_return;
    }

    ret = co_await this->read_bytes_n(uname, ulen);
    if (!ret) {
        this->stop();
        co_return;
    }

    ret = co_await this->read_byte(&plen);
    if (!ret) {
        this->stop();
        co_return;
    }

    if (plen == 0) {
        this->stop();
        co_return;
    }

    ret = co_await this->read_bytes_n(passwd, plen);
    if (!ret) {
        this->stop();
        co_return;
    }

    if (socks_config::get()->check_auth(uname, passwd)) {
        status = coro_socks::ReplyAuthStatus::Success;
    } else {
        status = coro_socks::ReplyAuthStatus::Failure;
    }

    std::array<asio::const_buffer, 2> buf = {
        {asio::buffer(&ver, 1), asio::buffer(&status, 1)}};

    asio::error_code ec;
    co_await asio::async_write(this->socket_, buf,
                               asio::redirect_error(asio::use_awaitable, ec));
    if (ec) {
        this->stop();
        co_return;
    }

    if (status == coro_socks::ReplyAuthStatus::Failure) {
        this->stop();
        co_return;
    }

    ret = co_await this->handle_connect();
    if (!ret) {
        co_await this->reply_and_stop(coro_socks::ReplyRep::ConnRefused);
        co_return;
    }

    co_return;
}

asio::awaitable<void> session::handle_client_request() {
    bool ret;
    uint8_t ver;
    uint8_t cmd;
    uint8_t rsv;
    uint8_t atyp;
    std::string dst_addr;
    uint16_t dst_port;

    ret = co_await this->read_byte(&ver);
    if (!ret) {
        this->stop();
        co_return;
    }

    if (ver != coro_socks::Version::V5) {
        this->stop();
        co_return;
    }

    ret = co_await this->read_byte(&cmd);
    if (!ret) {
        this->stop();
        co_return;
    }

    ret = co_await this->read_byte(&rsv);
    if (!ret) {
        this->stop();
        co_return;
    }

    if (rsv != 0x00) {
        this->stop();
        co_return;
    }

    ret = co_await this->read_byte(&atyp);
    if (!ret) {
        this->stop();
        co_return;
    }

    if (atyp == coro_socks::Atyp::IpV4) {
        ret = co_await this->read_bytes_n(dst_addr, 4);
        if (!ret) {
            this->stop();
            co_return;
        }
    } else if (atyp == coro_socks::Atyp::IpV6) {
        ret = co_await this->read_bytes_n(dst_addr, 16);
        if (!ret) {
            this->stop();
            co_return;
        }
    } else if (atyp == coro_socks::Atyp::DomainName) {
        /* this rsv use to domain length */
        ret = co_await this->read_byte(&rsv);
        if (!ret) {
            this->stop();
            co_return;
        }

        if (rsv == 0) {
            this->stop();
            co_return;
        }

        ret = co_await this->read_bytes_n(dst_addr, rsv);
        if (!ret) {
            this->stop();
            co_return;
        }
    } else {
        this->stop();
        co_return;
    }

    ret = co_await this->read_port(&dst_port);
    if (!ret) {
        this->stop();
        co_return;
    }

    switch (cmd) {
        case coro_socks::RequestCmd::Connect: {
            if (atyp == coro_socks::Atyp::DomainName) {
                co_await this->handle_dns_resolve(dst_addr, dst_port);
                co_return;
            }

            asio::error_code ec;
            auto addr = asio::ip::make_address(
                coro_socks::format_address(dst_addr, atyp), ec);
            if (ec) {
                this->stop();
                co_return;
            }

            this->tcp_dst_endpoint_ = asio::ip::tcp::endpoint(addr, dst_port);

            ret = co_await this->handle_connect();
            if (!ret) {
                co_await this->reply_and_stop(
                    coro_socks::ReplyRep::ConnRefused);
                co_return;
            }
            break;
        }
        case coro_socks::RequestCmd::UdpAssociate: {
            break;
        }
        default: {
            co_await this->reply_and_stop(
                coro_socks::ReplyRep::CommandNotSupported);
            break;
        }
    }

    co_return;
}

asio::awaitable<void> session::handle_dns_resolve(const std::string &dst_addr,
                                                  uint16_t dst_port) {
    bool ret;
    asio::error_code ec;
    asio::ip::tcp::resolver resolver(this->socket_.get_executor());

    auto endpoints = co_await resolver.async_resolve(
        dst_addr, std::to_string(dst_port),
        asio::redirect_error(asio::use_awaitable, ec));
    if (ec) {
        this->stop();
        co_return;
    }

    if (endpoints.empty()) {
        this->stop();
        co_return;
    }

    for (const auto &endpoint : endpoints) {
        this->tcp_dst_endpoint_ = endpoint;

        ret = co_await this->handle_connect();
        if (ret) {
            break;
        }
    }

    if (!ret) {
        co_await this->reply_and_stop(coro_socks::ReplyRep::ConnRefused);
        co_return;
    }

    co_return;
}

asio::awaitable<bool> session::handle_connect() {
    asio::error_code ec;
    uint8_t ver = coro_socks::Version::V5;
    uint8_t rep;
    uint8_t rsv = 0x00;
    uint8_t atyp;
    std::string bnd_addr;
    uint16_t bnd_port;

    co_await this->tcp_dst_socket_.async_connect(
        this->tcp_dst_endpoint_, asio::redirect_error(asio::use_awaitable, ec));

    if (ec) {
        co_return false;
    }

    auto tcp_bnd_endpoint = this->tcp_dst_socket_.local_endpoint(ec);
    if (ec) {
        co_return false;
    }

    if (tcp_bnd_endpoint.address().is_v4()) {
        atyp = coro_socks::Atyp::IpV4;
        auto &&addr_bytes = tcp_bnd_endpoint.address().to_v4().to_bytes();
        bnd_addr = std::string(addr_bytes.begin(), addr_bytes.end());
    } else {
        atyp = coro_socks::Atyp::IpV6;
        auto &&addr_bytes = tcp_bnd_endpoint.address().to_v6().to_bytes();
        bnd_addr = std::string(addr_bytes.begin(), addr_bytes.end());
    }

    rep = coro_socks::ReplyRep::Succeeded;

    bnd_port = asio::detail::socket_ops::host_to_network_short(
        tcp_bnd_endpoint.port());

    std::array<asio::const_buffer, 6> buf = {
        {asio::buffer(&ver, 1), asio::buffer(&rep, 1), asio::buffer(&rsv, 1),
         asio::buffer(&atyp, 1),
         asio::buffer(bnd_addr.data(), bnd_addr.length()),
         asio::buffer(&bnd_port, 2)}};

    co_await asio::async_write(this->socket_, buf,
                               asio::redirect_error(asio::use_awaitable, ec));
    if (ec) {
        co_return false;
    }

    asio::co_spawn(
        this->socket_.get_executor(),
        [self = shared_from_this()] {
            return self->handle_connect_cli_to_dst();
        },
        asio::detached);

    asio::co_spawn(
        this->socket_.get_executor(),
        [self = shared_from_this()] {
            return self->handle_connect_dst_to_cli();
        },
        asio::detached);

    co_return true;
}

asio::awaitable<void> session::handle_connect_cli_to_dst() {
    asio::error_code ec;
    char data[1024];

    for (;;) {
        this->flush_deadline();

        std::size_t n = co_await this->socket_.async_read_some(
            asio::buffer(data), asio::redirect_error(asio::use_awaitable, ec));
        if (ec) {
            this->stop();
            co_return;
        }

        co_await asio::async_write(
            this->tcp_dst_socket_, asio::buffer(data, n),
            asio::redirect_error(asio::use_awaitable, ec));
        if (ec) {
            this->stop();
            co_return;
        }
    }

    co_return;
}

asio::awaitable<void> session::handle_connect_dst_to_cli() {
    asio::error_code ec;
    char data[1024];

    for (;;) {
        this->flush_deadline();

        std::size_t n = co_await this->tcp_dst_socket_.async_read_some(
            asio::buffer(data), asio::redirect_error(asio::use_awaitable, ec));
        if (ec) {
            this->stop();
            co_return;
        }

        co_await asio::async_write(
            this->socket_, asio::buffer(data, n),
            asio::redirect_error(asio::use_awaitable, ec));
        if (ec) {
            this->stop();
            co_return;
        }
    }

    co_return;
}

asio::awaitable<void> session::reply_and_stop(uint8_t rep) {
    asio::error_code ec;
    uint8_t ver = coro_socks::Version::V5;
    uint8_t rsv = 0x00;
    uint8_t atyp = coro_socks::Atyp::IpV4;
    uint8_t bnd_addr[4] = {0};
    uint16_t bnd_port = 0;

    std::array<asio::const_buffer, 6> buf = {
        {asio::buffer(&ver, 1), asio::buffer(&rep, 1), asio::buffer(&rsv, 1),
         asio::buffer(&atyp, 1), asio::buffer(bnd_addr, 4),
         asio::buffer(&bnd_port, 2)}};

    co_await asio::async_write(this->socket_, buf,
                               asio::redirect_error(asio::use_awaitable, ec));
    if (!ec) {
        this->stop();
    }
    co_return;
}

asio::awaitable<bool> session::read_byte(uint8_t *addr) noexcept {
    asio::error_code ec;
    co_await asio::async_read(this->socket_, asio::buffer(addr, 1),
                              asio::redirect_error(asio::use_awaitable, ec));
    if (ec) {
        co_return false;
    }

    co_return true;
}

asio::awaitable<bool> session::read_port(uint16_t *port) noexcept {
    asio::error_code ec;
    uint8_t high, low;

    std::array<asio::mutable_buffer, 2> buf = {
        {asio::buffer(&high, 1), asio::buffer(&low, 1)}};

    co_await asio::async_read(this->socket_, buf,
                              asio::redirect_error(asio::use_awaitable, ec));
    if (ec) {
        co_return false;
    }

    *port = (uint16_t)(high << 8) + low;

    co_return true;
}

asio::awaitable<bool> session::read_bytes_n(std::string &bytes,
                                            uint32_t n) noexcept {
    asio::error_code ec;

    if (n == 0) {
        co_return true;
    }

    bytes.resize(n);

    co_await asio::async_read(this->socket_, asio::buffer(bytes.data(), n),
                              asio::redirect_error(asio::use_awaitable, ec));
    if (ec) {
        co_return false;
    }

    co_return true;
}
