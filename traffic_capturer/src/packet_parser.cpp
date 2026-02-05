#include "Packet_Parser.hpp"
#include <cstring>

std::optional<ParsedPacket> parse_packet(const Packet &pkt) {
    ParsedPacket out;

    const uint8_t* raw = pkt.data.data();
    size_t caplen = pkt.caplen;

    if (caplen < sizeof(EthernetHeader)) return std::nullopt;
    const EthernetHeader* eth = reinterpret_cast<const EthernetHeader*>(raw);
    out.ethertype = eth->ntoh_ethertype();

    // Only IPv4 for now
    if (out.ethertype != 0x0800) {
        return std::nullopt;
    }

    // ---------------- IPv4 ----------------
    size_t ip_off = sizeof(EthernetHeader);
    if (caplen < ip_off + sizeof(IPv4Header)) {
        return std::nullopt;
    }

    const IPv4Header* ip =
        reinterpret_cast<const IPv4Header*>(raw + ip_off);

    size_t ip_hdr_len = ip->header_length_bytes();
    if (ip_hdr_len < 20) {
        return std::nullopt;
    }

    if (caplen < ip_off + ip_hdr_len) {
        return std::nullopt;
    }

    out.is_ipv4 = true;
    out.ip_proto = ip->protocol;
    out.ip_header_len = ip_hdr_len;
    out.src_ip = format_ipv4(ip->ntoh_src_addr());
    out.dst_ip = format_ipv4(ip->ntoh_dst_addr());

    // ---------------- Fragmentation ----------------
    uint16_t frag_field = ntohs(ip->flags_fragment);
    uint16_t frag_offset = frag_field & 0x1FFF;     // lower 13 bits
    bool more_fragments = frag_field & 0x2000;      // MF flag

    if (frag_offset != 0 || more_fragments) {
        out.is_fragment = true;
    }

    // ---------------- Transport / Payload ----------------
    size_t l4_off = ip_off + ip_hdr_len;

    // Default payload assumption (safe fallback)
    out.payload = raw + l4_off;
    out.payload_len = (l4_off < caplen) ? (caplen - l4_off) : 0;

    // ---- TCP ----
    if (out.ip_proto == 6 && !out.is_fragment) {
        if (caplen < l4_off + sizeof(TCPHeader)) {
            return std::nullopt;
        }

        const TCPHeader* tcp =
            reinterpret_cast<const TCPHeader*>(raw + l4_off);

        size_t tcp_len = tcp->header_length_bytes();
        if (tcp_len < 20) {
            return std::nullopt;
        }

        if (caplen < l4_off + tcp_len) {
            return std::nullopt;
        }

        out.is_tcp = true;
        out.has_ports = true;
        out.src_port = tcp->ntoh_src_port();
        out.dst_port = tcp->ntoh_dst_port();
        out.l4_header_len = tcp_len;

        out.payload = raw + l4_off + tcp_len;
        out.payload_len =
            (l4_off + tcp_len < caplen)
                ? (caplen - (l4_off + tcp_len))
                : 0;
    }

    // ---- UDP ----
    else if (out.ip_proto == 17 && !out.is_fragment) {
        if (caplen < l4_off + sizeof(UDPHeader)) {
            return std::nullopt;
        }

        const UDPHeader* udp =
            reinterpret_cast<const UDPHeader*>(raw + l4_off);

        out.is_udp = true;
        out.has_ports = true;
        out.src_port = udp->ntoh_src_port();
        out.dst_port = udp->ntoh_dst_port();
        out.l4_header_len = sizeof(UDPHeader);

        out.payload = raw + l4_off + out.l4_header_len;
        out.payload_len =
            (l4_off + out.l4_header_len < caplen)
                ? (caplen - (l4_off + out.l4_header_len))
                : 0;
    }

    // ---- ICMP ----
    else if (out.ip_proto == 1) {
        out.is_icmp = true;
        out.has_ports = false;
        out.l4_header_len = 0;
        // payload already set correctly after IP header
    }

    // ---- Other L4 protocols ----
    else {
        out.is_other_l4 = true;
        out.has_ports = false;
        out.l4_header_len = 0;
    }

    return out;
}


