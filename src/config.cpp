#include "config.h"

#include "yaml-cpp/yaml.h"

socks_config* socks_config::get() {
    static socks_config config;
    return &config;
}

socks_config::socks_config()
    : address_("127.0.0.1"),
      port_(1080),
      worker_process_num_(std::thread::hardware_concurrency()),
      keep_alive_time_(30),
      check_duration_(1),
      auth_(false) {}

bool socks_config::parse(const std::string& file) {
    YAML::Node root;
    try {
        root = YAML::LoadFile(file);

        if (!root["server"].IsDefined()) {
            return true;
        }

        auto nodeServer = root["server"];

        if (nodeServer["address"].IsDefined()) {
            this->address_ = nodeServer["address"].as<std::string>();
        }

        if (nodeServer["port"].IsDefined()) {
            this->port_ = nodeServer["port"].as<uint16_t>();
        }

        if (nodeServer["worker_process_num"].IsDefined()) {
            auto num = nodeServer["worker_process_num"].as<uint32_t>();
            if (num > 0) {
                this->worker_process_num_ = num;
            }
        }

        if (!nodeServer["protocol"].IsDefined()) {
            return true;
        }

        auto nodeProtocol = nodeServer["protocol"];

        if (nodeProtocol["keep_alive_time"].IsDefined()) {
            this->keep_alive_time_ =
                nodeProtocol["keep_alive_time"].as<uint32_t>();
        }

        if (nodeProtocol["check_duration"].IsDefined()) {
            this->check_duration_ =
                nodeProtocol["check_duration"].as<uint32_t>();
        }

        if (nodeProtocol["auth"].IsDefined()) {
            this->auth_ = nodeProtocol["auth"].as<bool>();
        }

        if (this->auth_ && nodeProtocol["credentials"].IsDefined()) {
            for (const auto& credential : nodeProtocol["credentials"]) {
                auto username = credential["username"].as<std::string>();
                auto password = credential["password"].as<std::string>();

                this->credentials_[username] = password;
            }
        }
    } catch (const std::exception& e) {
        std::printf("failed to parse config file: [%s], error info: [%s]\n",
                    file.c_str(), e.what());
        return false;
    }

    return true;
}

bool socks_config::check_auth(const std::string& username,
                              const std::string& password) {
    if (this->auth_) {
        if (this->credentials_.count(username) &&
            this->credentials_[username] == password) {
            return true;
        }
        return false;
    }

    return true;
}