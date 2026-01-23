#pragma once
#include "Packet.hpp"
#include "Headers.hpp"
#include <optional>
#include <string>

struct ParsedPacket {
    // ---------- Ethernet ----------
    uint16_t ethertype{0};

    // ---------- IP ----------
    bool is_ipv4{false};
    std::string src_ip;
    std::string dst_ip;
    uint8_t ip_proto{0};
    size_t ip_header_len{0};

    // Fragmentation info
    bool is_fragment{false};

    // ---------- Transport ----------
    bool is_tcp{false};
    bool is_udp{false};
    bool is_icmp{false};
    bool is_other_l4{false};

    bool has_ports{false};
    uint16_t src_port{0};
    uint16_t dst_port{0};
    size_t l4_header_len{0};

    // ---------- Payload ----------
    const uint8_t* payload{nullptr};
    size_t payload_len{0};
};

std::optional<ParsedPacket> parse_packet(const Packet &pkt);
