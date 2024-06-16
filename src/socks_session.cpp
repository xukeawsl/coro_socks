#include "socks_session.h"

socks_session::socks_session(asio::ip::tcp::socket socket)
    : socket_(std::move(socket)),
      keep_alive_time_(socks_config::get()->keep_alive_time()),
      keep_alive_timer_(socket_.get_executor()),
      tcp_dst_socket_(socket_.get_executor()) {
    this->keep_alive_timer_.expires_at(
        std::chrono::steady_clock::time_point::max());
}

socks_session::~socks_session() {}

void socks_session::start() {
    asio::error_code ec;

    this->client_endpoint_ = this->socket_.remote_endpoint(ec);
    if (ec) {
        return;
    }

    this->proxy_endpoint_ = this->socket_.local_endpoint(ec);
    if (ec) {
        return;
    }

    this->flush_deadline();

    asio::co_spawn(
        this->socket_.get_executor(),
        [self = getDerivedSharedPtr<socks_session>()] {
            return self->handle_packet();
        },
        asio::detached);

    asio::co_spawn(
        this->socket_.get_executor(),
        [self = getDerivedSharedPtr<socks_session>()] {
            return self->handle_keep_alive();
        },
        asio::detached);
}

void socks_session::flush_deadline() {
    this->deadline_ = std::chrono::steady_clock::now() +
                      std::chrono::seconds(this->keep_alive_time_);
}

void socks_session::stop() {
    asio::error_code ignored_ec;
    this->socket_.close(ignored_ec);
    this->keep_alive_timer_.cancel(ignored_ec);
    this->tcp_dst_socket_.close(ignored_ec);
}

asio::awaitable<void> socks_session::handle_keep_alive() {
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

asio::awaitable<void> socks_session::handle_packet() {
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
        default: {
            this->stop();
            break;
        }
    }

    co_return;
}

asio::awaitable<void> socks_session::handle_authentication() {
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

    if (ver != 0x01) {
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

    co_await this->handle_client_request();

    co_return;
}

asio::awaitable<void> socks_session::handle_client_request() {
    bool ret;
    asio::error_code ec;
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
            bool connect_success = false;

            if (atyp == coro_socks::Atyp::DomainName) {
                asio::ip::tcp::resolver resolver(this->socket_.get_executor());
                auto endpoints = co_await resolver.async_resolve(
                    dst_addr, std::to_string(dst_port),
                    asio::redirect_error(asio::use_awaitable, ec));

                if (ec) {
                    this->stop();
                    co_return;
                }

                /*try to connect one endpoint from all endpoints*/
                for (auto &&endpoint : endpoints) {
                    co_await this->tcp_dst_socket_.async_connect(
                        endpoint,
                        asio::redirect_error(asio::use_awaitable, ec));
                    if (!ec) {
                        connect_success = true;
                        break;
                    }
                }

            } else {
                auto addr = asio::ip::make_address(
                    coro_socks::format_address(dst_addr, atyp), ec);
                if (ec) {
                    this->stop();
                    co_return;
                }

                /*connect to the dst host*/
                co_await this->tcp_dst_socket_.async_connect(
                    asio::ip::tcp::endpoint(addr, dst_port),
                    asio::redirect_error(asio::use_awaitable, ec));
                if (!ec) {
                    connect_success = true;
                }
            }

            if (!connect_success) {
                co_await this->reply_and_stop(
                    coro_socks::ReplyRep::ConnRefused);
                co_return;
            }

            co_await this->handle_connect();

            break;
        }
        case coro_socks::RequestCmd::UdpAssociate: {
            if (atyp == coro_socks::Atyp::DomainName) {
                asio::ip::udp::resolver resolver(this->socket_.get_executor());
                auto endpoints = co_await resolver.async_resolve(
                    dst_addr, std::to_string(dst_port),
                    asio::redirect_error(asio::use_awaitable, ec));

                if (endpoints.empty()) {
                    co_await this->reply_and_stop(
                        coro_socks::ReplyRep::HostUnreachable);
                    co_return;
                }

                this->udp_endpoints_ = std::vector<asio::ip::udp::endpoint>(
                    endpoints.begin(), endpoints.end());
            } else {
                auto addr = asio::ip::make_address(
                    coro_socks::format_address(dst_addr, atyp), ec);
                if (ec) {
                    this->stop();
                    co_return;
                }

                this->udp_endpoints_.emplace_back(addr, dst_port);
            }

            co_await this->handle_udp_associate();

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

asio::awaitable<void> socks_session::handle_connect() {
    asio::error_code ec;
    uint8_t ver = coro_socks::Version::V5;
    uint8_t rep = coro_socks::ReplyRep::Succeeded;
    uint8_t rsv = 0x00;
    uint8_t atyp;
    std::string bnd_addr;
    uint16_t bnd_port;

    auto tcp_bnd_endpoint = this->tcp_dst_socket_.local_endpoint(ec);
    if (ec) {
        this->stop();
        co_return;
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
        this->stop();
        co_return;
    }

    asio::co_spawn(
        this->socket_.get_executor(),
        [self = getDerivedSharedPtr<socks_session>()] {
            return self->handle_connect_cli_to_dst();
        },
        asio::detached);

    asio::co_spawn(
        this->socket_.get_executor(),
        [self = getDerivedSharedPtr<socks_session>()] {
            return self->handle_connect_dst_to_cli();
        },
        asio::detached);

    co_return;
}

asio::awaitable<void> socks_session::handle_connect_cli_to_dst() {
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

asio::awaitable<void> socks_session::handle_connect_dst_to_cli() {
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

asio::awaitable<void> socks_session::handle_udp_associate() {
    asio::error_code ec;
    uint8_t ver = coro_socks::Version::V5;
    uint8_t rep = coro_socks::ReplyRep::Succeeded;
    uint8_t rsv = 0x00;
    uint8_t atyp;
    std::string bnd_addr;
    uint16_t bnd_port;

    if (this->udp_endpoints_[0].address().is_v4()) {
        atyp = coro_socks::Atyp::IpV4;

        this->udp_socket_ = std::make_unique<asio::ip::udp::socket>(
            this->socket_.get_executor(),
            asio::ip::udp::endpoint(asio::ip::udp::v4(), 0));
    } else {
        atyp = coro_socks::Atyp::IpV6;

        this->udp_socket_ = std::make_unique<asio::ip::udp::socket>(
            this->socket_.get_executor(),
            asio::ip::udp::endpoint(asio::ip::udp::v6(), 0));
    }

    this->udp_bnd_endpoint_ = this->udp_socket_->local_endpoint(ec);
    if (ec) {
        this->stop();
        co_return;
    }

    if (this->udp_bnd_endpoint_.address().is_v4()) {
        auto &&addr_bytes =
            this->udp_bnd_endpoint_.address().to_v4().to_bytes();
        bnd_addr = std::string(addr_bytes.begin(), addr_bytes.end());
    } else {
        auto &&addr_bytes =
            this->udp_bnd_endpoint_.address().to_v6().to_bytes();
        bnd_addr = std::string(addr_bytes.begin(), addr_bytes.end());
    }

    bnd_port = asio::detail::socket_ops::host_to_network_short(
        this->udp_bnd_endpoint_.port());

    std::array<asio::const_buffer, 6> buf = {
        {asio::buffer(&ver, 1), asio::buffer(&rep, 1), asio::buffer(&rsv, 1),
         asio::buffer(&atyp, 1),
         asio::buffer(bnd_addr.data(), bnd_addr.length()),
         asio::buffer(&bnd_port, 2)}};

    co_await asio::async_write(this->socket_, buf,
                               asio::redirect_error(asio::use_awaitable, ec));
    if (ec) {
        this->stop();
        co_return;
    }

    SPDLOG_DEBUG(
        "UDP ASSOCIATE - [TCP Proxy: {} -> TCP Client: {}] VER = [X'{:02X}'], "
        "REP = "
        "[X'{:02X}'], RSV = [X'{:02X}'], ATYP = [X'{:02X}'], "
        "BND.ADDR = [{}], BND.PORT = [{}]",
        coro_socks::format_address(this->proxy_endpoint_),
        coro_socks::format_address(this->client_endpoint_),
        static_cast<uint16_t>(ver), static_cast<uint16_t>(rep),
        static_cast<uint16_t>(rsv), static_cast<uint16_t>(atyp),
        this->udp_bnd_endpoint_.address().is_v4()
            ? this->udp_bnd_endpoint_.address().to_v4().to_string()
            : this->udp_bnd_endpoint_.address().to_v6().to_string(),
        this->udp_bnd_endpoint_.port());

    asio::co_spawn(
        this->socket_.get_executor(),
        [self = getDerivedSharedPtr<socks_session>()] {
            return self->handle_udp_associate_detail();
        },
        asio::detached);

    co_return;
}

bool socks_session::check_udp_sender_endpoint(
    const asio::ip::udp::endpoint &sender_endpoint) {
    for (auto &&udp_endpoint : this->udp_endpoints_) {
        if (sender_endpoint == udp_endpoint) {
            return true;
        }
    }

    return false;
}

asio::awaitable<void> socks_session::handle_udp_associate_detail() {
    asio::error_code ec;
    std::string buf(UINT16_MAX, 0);
    uint16_t rsv;
    uint8_t frag;
    uint8_t atyp;
    std::string_view dst_addr;
    uint16_t dst_port;
    std::string_view data;
    asio::ip::udp::endpoint sender_endpoint;
    asio::ip::udp::endpoint udp_cli_endpoint;
    asio::ip::udp::endpoint udp_dst_endpoint;

    while (this->socket_.is_open()) {
        this->flush_deadline();

        std::size_t length = co_await this->udp_socket_->async_receive_from(
            asio::buffer(buf), sender_endpoint,
            asio::redirect_error(asio::use_awaitable, ec));
        if (ec) {
            this->stop();
            co_return;
        }

        /* dst to cli */
        if (!udp_dst_endpoint.address().is_unspecified() &&
            sender_endpoint == udp_dst_endpoint) {
            rsv = 0x00;
            frag = 0x00;
            std::string addr_bytes;

            if (udp_dst_endpoint.address().is_v4()) {
                atyp = coro_socks::Atyp::IpV4;
                auto bytes = udp_dst_endpoint.address().to_v4().to_bytes();
                addr_bytes = std::string(bytes.begin(), bytes.end());
            } else {
                atyp = coro_socks::Atyp::IpV6;
                auto bytes = udp_dst_endpoint.address().to_v6().to_bytes();
                addr_bytes = std::string(bytes.begin(), bytes.end());
            }

            dst_port = asio::detail::socket_ops::host_to_network_short(
                udp_dst_endpoint.port());

            std::array<asio::const_buffer, 6> reply_buf = {
                {asio::buffer(&rsv, 2), asio::buffer(&frag, 1),
                 asio::buffer(&atyp, 1),
                 asio::buffer(addr_bytes.data(), addr_bytes.length()),
                 asio::buffer(&dst_port, 2), asio::buffer(buf.data(), length)}};

            co_await this->udp_socket_->async_send_to(
                reply_buf, udp_cli_endpoint,
                asio::redirect_error(asio::use_awaitable, ec));

            SPDLOG_DEBUG(
                "UDP ASSOCIATE - [UDP Proxy {} -> UDP Client {}] RSV = "
                "[X'{:04X}'], "
                "FRAG = [X'{:02X}'],"
                "ATYP = [X'{:02X}'], DST.ADDR = [{}], DST.PORT = [{}]",
                coro_socks::format_address(this->udp_bnd_endpoint_),
                coro_socks::format_address(udp_cli_endpoint), rsv,
                static_cast<uint16_t>(frag), static_cast<uint16_t>(atyp),
                coro_socks::format_address(addr_bytes, atyp),
                udp_dst_endpoint.port());

            continue;
        }

        if (!this->udp_endpoints_[0].address().is_unspecified() &&
            !this->check_udp_sender_endpoint(sender_endpoint)) {
            continue;
        }

        udp_cli_endpoint = sender_endpoint;

        /* this is a client request */
        if (length <= 4) {
            continue;
        }

        rsv = static_cast<uint16_t>(buf[0] << 8) + buf[1];
        if (rsv != 0x0000) {
            continue;
        }

        frag = buf[2];
        if (frag) {
            continue;
        }

        atyp = buf[3];

        switch (atyp) {
            case coro_socks::Atyp::IpV4: {
                if (length <= static_cast<std::size_t>(4 + 4 + 2)) {
                    continue;
                }

                dst_addr = std::string_view(buf.begin() + 4, buf.begin() + 8);
                dst_port = static_cast<uint16_t>(buf[8] << 8) + buf[9];
                data = std::string_view(buf.begin() + 10, buf.begin() + length);
                break;
            }
            case coro_socks::Atyp::IpV6: {
                if (length <= static_cast<std::size_t>(4 + 16 + 2)) {
                    continue;
                }

                dst_addr = std::string_view(buf.begin() + 4, buf.begin() + 20);
                dst_port = static_cast<uint16_t>(buf[20] << 8) + buf[21];
                data = std::string_view(buf.begin() + 22, buf.begin() + length);
                break;
            }
            case coro_socks::Atyp::DomainName: {
                uint8_t dlen = buf[4];

                if (length <= static_cast<std::size_t>(4 + 1 + dlen + 2)) {
                    continue;
                }

                dst_addr =
                    std::string_view(buf.begin() + 5, buf.begin() + 5 + dlen);
                dst_port = static_cast<uint16_t>(buf[5 + dlen] << 8) +
                           buf[5 + dlen + 1];
                data = std::string_view(buf.begin() + 7 + dlen,
                                        buf.begin() + length);
                break;
            }
            default: {
                continue;
            }
        };

        SPDLOG_DEBUG(
            "UDP ASSOCIATE - [UDP Client {} -> UDP Proxy {}] RSV = "
            "[X'{:04X}'], FRAG = "
            "[X'{:02X}'], "
            "ATYP = [X'{:02X}'], DST.ADDR = [{}], DST.PORT = [{}]",
            coro_socks::format_address(udp_cli_endpoint),
            coro_socks::format_address(this->udp_bnd_endpoint_), rsv,
            static_cast<uint16_t>(frag), static_cast<uint16_t>(atyp),
            coro_socks::format_address(dst_addr, atyp), dst_port);

        std::vector<asio::ip::udp::endpoint> udp_dst_endpoints;

        if (atyp == coro_socks::Atyp::DomainName) {
            asio::ip::udp::resolver resolver(this->socket_.get_executor());

            auto endpoints = co_await resolver.async_resolve(
                dst_addr, std::to_string(dst_port),
                asio::redirect_error(asio::use_awaitable, ec));
            if (ec) {
                continue;
            }

            udp_dst_endpoints = std::vector<asio::ip::udp::endpoint>(
                endpoints.begin(), endpoints.end());
        } else {
            auto addr = asio::ip::make_address(
                coro_socks::format_address(dst_addr, atyp), ec);
            if (ec) {
                continue;
            }

            udp_dst_endpoints.emplace_back(addr, dst_port);
        }

        for (auto &&endpoint : udp_dst_endpoints) {
            co_await this->udp_socket_->async_send_to(
                asio::buffer(data.data(), data.length()), endpoint,
                asio::redirect_error(asio::use_awaitable, ec));

            if (ec) {
                SPDLOG_DEBUG("UDP ASSOCIATE - failed to send udp [{}]",
                             ec.message());
                continue;
            } else {
                SPDLOG_DEBUG(
                    "UDP ASSOCIATE - [UDP Proxy {} -> UDP Server {}] "
                    "Data Length = [{}]",
                    coro_socks::format_address(this->udp_bnd_endpoint_),
                    coro_socks::format_address(endpoint), data.length());

                udp_dst_endpoint = endpoint;
                break;
            }
        }
    }

    co_return;
}

asio::awaitable<void> socks_session::reply_and_stop(uint8_t rep) {
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

asio::awaitable<bool> socks_session::read_byte(uint8_t *addr) noexcept {
    asio::error_code ec;
    co_await asio::async_read(this->socket_, asio::buffer(addr, 1),
                              asio::redirect_error(asio::use_awaitable, ec));
    if (ec) {
        co_return false;
    }

    co_return true;
}

asio::awaitable<bool> socks_session::read_port(uint16_t *port) noexcept {
    asio::error_code ec;
    uint8_t high, low;

    std::array<asio::mutable_buffer, 2> buf = {
        {asio::buffer(&high, 1), asio::buffer(&low, 1)}};

    co_await asio::async_read(this->socket_, buf,
                              asio::redirect_error(asio::use_awaitable, ec));
    if (ec) {
        co_return false;
    }

    *port = static_cast<uint16_t>(high << 8) + low;

    co_return true;
}

asio::awaitable<bool> socks_session::read_bytes_n(std::string &bytes,
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
