#pragma once

#include <thread>
#include <string>
#include <unordered_map>

#include "asiomp.h"

namespace coro_socks {
// clang-format off
struct Version {
    static constexpr uint8_t V4                     = 0x04;
    static constexpr uint8_t V5                     = 0x05;
};

struct Atyp {
    static constexpr uint8_t IpV4                   = 0x01;
    static constexpr uint8_t DomainName             = 0x03;
    static constexpr uint8_t IpV6                   = 0x04;
};

struct Method {
    static constexpr uint8_t NoAuth                 = 0x00;
    static constexpr uint8_t GSSAPI                 = 0x01;
    static constexpr uint8_t UserPassWd             = 0x02;
    static constexpr uint8_t NoAcceptable           = 0xFF;
};

struct ReplyAuthStatus {
    static constexpr uint8_t Success                = 0x00;
    static constexpr uint8_t Failure                = 0xFF;
};

struct RequestCmd {
    static constexpr uint8_t Connect                = 0x01;
    static constexpr uint8_t Bind                   = 0x02;
    static constexpr uint8_t UdpAssociate           = 0x03;
};

struct ReplyRep {
    static constexpr uint8_t Succeeded              = 0x00;
    static constexpr uint8_t GenServFailed          = 0x01;
    static constexpr uint8_t NotAllowed             = 0x02;
    static constexpr uint8_t NetworkUnreachable     = 0x03;
    static constexpr uint8_t HostUnreachable        = 0x04;
    static constexpr uint8_t ConnRefused            = 0x05;
    static constexpr uint8_t TtlExpired             = 0x06;
    static constexpr uint8_t CommandNotSupported    = 0x07;
    static constexpr uint8_t AddrTypeNotSupported   = 0x08;
};
// clang-format on


std::string format_address(std::string_view bytes, uint8_t atyp);


template <typename InternetProtocol>
std::string format_address(
    const asio::ip::basic_endpoint<InternetProtocol>& endpoint) {
    if (endpoint.address().is_v6()) {
        return "[" + endpoint.address().to_string() + "]" + ":" +
               std::to_string(endpoint.port());
    }
    return endpoint.address().to_string() + ":" +
           std::to_string(endpoint.port());
}

}



