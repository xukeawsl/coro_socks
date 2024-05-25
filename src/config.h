#pragma once

#include "public.h"

class socks_config {

public:
    static socks_config* get();

    bool parse(const std::string& file);

    bool check_auth(const std::string& username, const std::string& password);

    inline std::string address() const { return this->address_; }

    inline uint16_t port() const { return this->port_; }

    inline uint32_t worker_process_num() const { return this->worker_process_num_; }

    inline uint32_t keep_alive_time() const { return this->keep_alive_time_; }

    inline uint32_t check_duration() const { return this->check_duration_; }

    inline bool auth() const { return this->auth_; }

private:
    socks_config();

    ~socks_config() = default;

    socks_config(const socks_config&) = delete;

    socks_config& operator=(const socks_config&) = delete;

    socks_config(socks_config&&) = delete;

    socks_config& operator=(socks_config&&) = delete;

private:
    std::string address_;
    uint16_t port_;
    uint32_t worker_process_num_;
    uint32_t keep_alive_time_;
    uint32_t check_duration_;
    bool auth_;
    std::unordered_map<std::string, std::string> credentials_;
};