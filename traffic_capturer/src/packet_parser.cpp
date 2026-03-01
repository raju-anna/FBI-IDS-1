#include "Packet_Parser.hpp"

bool parse_packet(const Packet &pkt, ParsedPacket &out) noexcept
{
    out.reset();

    const uint8_t *raw    = pkt.data.data();   // std::vector — must call .data()
    const size_t   caplen = pkt.caplen;

    // ── Ethernet ─────────────────────────────────────────────────────────
    if (caplen < sizeof(EthernetHeader)) return false;
    const auto *eth = reinterpret_cast<const EthernetHeader *>(raw);
    out.ethertype   = eth->ntoh_ethertype();

    // ── VLAN (802.1Q) transparent skip ───────────────────────────────────
    size_t   ip_off = sizeof(EthernetHeader);
    uint16_t etype  = out.ethertype;
    if (etype == 0x8100) {
        if (caplen < ip_off + 4) return false;
        etype   = ntohs(*reinterpret_cast<const uint16_t *>(raw + ip_off + 2));
        ip_off += 4;
    }

    if (etype != 0x0800) return false;   // IPv4 only

    // ── IPv4 ─────────────────────────────────────────────────────────────
    if (caplen < ip_off + sizeof(IPv4Header)) return false;
    const auto *ip = reinterpret_cast<const IPv4Header *>(raw + ip_off);

    if (ip->version() != 4) return false;

    const uint16_t ip_total_len = ip->ntoh_total_length();
    const size_t   ip_hdr_len   = ip->header_length_bytes();

    if (ip_hdr_len < 20)               return false;
    if (caplen < ip_off + ip_hdr_len)  return false;
    if (ip_total_len < ip_hdr_len)     return false;

    out.is_ipv4       = true;
    out.ip_proto      = ip->protocol;
    out.ip_header_len = static_cast<uint16_t>(ip_hdr_len);
    out.ip_total_len  = ip_total_len;   // CIC uses ip_total_len, NOT caplen
    out.src_ip        = ip->ntoh_src_addr();
    out.dst_ip        = ip->ntoh_dst_addr();

    // ── Fragmentation — drop; reassembly not supported ───────────────────
    const uint16_t frag_field  = ntohs(ip->flags_fragment);
    const uint16_t frag_offset = frag_field & 0x1FFF;
    const bool     more_frags  = (frag_field & 0x2000) != 0;
    out.is_fragment = (frag_offset != 0 || more_frags);

    const size_t l4_off = ip_off + ip_hdr_len;

    // ── TCP ──────────────────────────────────────────────────────────────
    if (ip->protocol == 6 && !out.is_fragment) {
        if (caplen < l4_off + sizeof(TCPHeader)) return false;
        const auto *tcp = reinterpret_cast<const TCPHeader *>(raw + l4_off);

        const size_t tcp_len = tcp->header_length_bytes();
        if (tcp_len < 20)               return false;
        if (caplen < l4_off + tcp_len)  return false;

        out.is_tcp         = true;
        out.has_ports      = true;
        out.src_port       = tcp->ntoh_src_port();
        out.dst_port       = tcp->ntoh_dst_port();
        out.tcp_header_len = static_cast<uint16_t>(tcp_len);
        out.tcp_window     = ntohs(tcp->window);
        out.tcp_flags      = tcp->flags;

        // Payload length = ip_total_len - ip_hdr - tcp_hdr (CIC semantics)
        const int32_t pay = static_cast<int32_t>(ip_total_len)
                          - static_cast<int32_t>(ip_hdr_len)
                          - static_cast<int32_t>(tcp_len);
        out.payload_len = (pay > 0) ? static_cast<uint32_t>(pay) : 0;
        const size_t pay_off = l4_off + tcp_len;
        out.payload = (out.payload_len > 0 && pay_off < caplen)
                      ? raw + pay_off : nullptr;

    // ── UDP ──────────────────────────────────────────────────────────────
    } else if (ip->protocol == 17 && !out.is_fragment) {
        if (caplen < l4_off + sizeof(UDPHeader)) return false;
        const auto *udp = reinterpret_cast<const UDPHeader *>(raw + l4_off);

        out.is_udp         = true;
        out.has_ports      = true;
        out.src_port       = udp->ntoh_src_port();
        out.dst_port       = udp->ntoh_dst_port();
        out.tcp_header_len = 8;   // HeaderStats treats UDP header as 8 bytes
        out.tcp_window     = 0;
        out.tcp_flags      = 0;

        const int32_t pay = static_cast<int32_t>(ip_total_len)
                          - static_cast<int32_t>(ip_hdr_len) - 8;
        out.payload_len = (pay > 0) ? static_cast<uint32_t>(pay) : 0;
        const size_t pay_off = l4_off + 8;
        out.payload = (out.payload_len > 0 && pay_off < caplen)
                      ? raw + pay_off : nullptr;

    // ── ICMP ─────────────────────────────────────────────────────────────
    } else if (ip->protocol == 1) {
        out.is_icmp        = true;
        out.tcp_header_len = 0;
        out.tcp_window     = 0;
        out.tcp_flags      = 0;
        out.payload_len    = 0;

    // ── Other L4 ─────────────────────────────────────────────────────────
    } else {
        out.is_other_l4    = true;
        out.tcp_header_len = 0;
        out.tcp_window     = 0;
        out.tcp_flags      = 0;
        out.payload_len    = 0;
    }

    return true;
}