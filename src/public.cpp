#include "public.h"

namespace coro_socks {

std::string format_address(const std::string& bytes, uint8_t atyp) {
    switch (atyp) {
        case Atyp::IpV4: {
            return fmt::format("{:d}.{:d}.{:d}.{:d}", bytes[0], bytes[1],
                               bytes[2], bytes[3]);
        }
        case Atyp::IpV6: {
            return fmt::format(
                "{:02X}{:02X}:{:02X}{:02X}:{:02X}{:02X}:{:02X}{:02X}:"
                "{:02X}{:02X}:{:02X}{:02X}:{:02X}{:02X}:{:02X}{:02X}",
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
                bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
                bytes[12], bytes[13], bytes[14], bytes[15]);
        }
        default: {
            break;
        }
    }

    return bytes;
}

}    // namespace coro_socks