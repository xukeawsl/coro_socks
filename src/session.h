#pragma once

#include "asiomp.h"

class session
  : public std::enable_shared_from_this<session>
{
public:
    session(asio::ip::tcp::socket socket);

    ~session();

    void start();

private:
    void stop();

    void flush_deadline();

    asio::awaitable<void> handle_keep_alive();

    asio::awaitable<void> handle_packet();

    asio::awaitable<void> handle_authentication();

    asio::awaitable<void> handle_client_request();

    asio::awaitable<void> handle_connect();

    asio::awaitable<void> handle_connect_cli_to_dst();

    asio::awaitable<void> handle_connect_dst_to_cli();

    asio::awaitable<void> handle_udp_associate();

    bool check_udp_sender_endpoint(const asio::ip::udp::endpoint& sender_endpoint);

    asio::awaitable<void> handle_udp_associate_detail();

    asio::awaitable<void> reply_and_stop(uint8_t rep);

    asio::awaitable<bool> read_byte(uint8_t *addr) noexcept;

    asio::awaitable<bool> read_port(uint16_t *port) noexcept;

    asio::awaitable<bool> read_bytes_n(std::string& bytes, uint32_t n) noexcept;

private:
    asio::ip::tcp::socket socket_;
    uint32_t keep_alive_time_;
    asio::steady_timer keep_alive_timer_;
    std::chrono::steady_clock::time_point deadline_;

    asio::ip::tcp::endpoint client_endpoint_;
    asio::ip::tcp::endpoint proxy_endpoint_;
    asio::ip::tcp::socket tcp_dst_socket_;

    std::vector<asio::ip::udp::endpoint> udp_endpoints_;
    std::unique_ptr<asio::ip::udp::socket> udp_socket_;
    asio::ip::udp::endpoint udp_bnd_endpoint_;
};