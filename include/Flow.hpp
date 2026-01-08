#pragma once

#include <cstdint>
#include <string>
#include <limits>
#include <chrono>
#include <functional>

struct FlowKey
{
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;

    FlowKey(const std::string &s_ip,
            const std::string &d_ip,
            uint16_t s_port,
            uint16_t d_port,
            uint8_t proto)
        : src_ip(s_ip),
          dst_ip(d_ip),
          src_port(s_port),
          dst_port(d_port),
          protocol(proto) {}

    bool operator==(const FlowKey &other) const
    {
        return src_ip == other.src_ip &&
               dst_ip == other.dst_ip &&
               src_port == other.src_port &&
               dst_port == other.dst_port &&
               protocol == other.protocol;
    }
};

struct FlowKeyHash
{
    std::size_t operator()(const FlowKey &k) const
    {
        std::size_t h1 = std::hash<std::string>{}(k.src_ip);
        std::size_t h2 = std::hash<std::string>{}(k.dst_ip);
        std::size_t h3 = std::hash<uint16_t>{}(k.src_port);
        std::size_t h4 = std::hash<uint16_t>{}(k.dst_port);
        std::size_t h5 = std::hash<uint8_t>{}(k.protocol);

        return (((h1 ^ (h2 << 1)) ^ (h3 << 1)) ^ (h4 << 1)) ^ (h5 << 1);
    }
};

struct Flow
{

    FlowKey key;

    uint64_t start_ts_us;
    uint64_t last_seen_ts_us;

    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;

    uint64_t fwd_pkts = 0;
    uint64_t bwd_pkts = 0;
    uint64_t fwd_bytes = 0;
    uint64_t bwd_bytes = 0;

    uint64_t sum_pkt_len = 0;
    uint32_t min_pkt_len = std::numeric_limits<uint32_t>::max();
    uint32_t max_pkt_len = 0;

    uint32_t syn_count = 0;
    uint32_t ack_count = 0;
    uint32_t fin_count = 0;
    uint32_t rst_count = 0;
    uint32_t psh_count = 0;

    Flow(const FlowKey& k, uint64_t ts_us)
    : key(k),
      start_ts_us(ts_us),
      last_seen_ts_us(ts_us) {}

    void update(uint64_t ts_us,
                uint32_t pkt_len,
                bool forward,
                bool syn,
                bool ack,
                bool fin,
                bool rst,
                bool psh)
    {
        last_seen_ts_us = ts_us;
        total_packets++;
        total_bytes += pkt_len;
        sum_pkt_len += pkt_len;

        if (pkt_len < min_pkt_len) min_pkt_len = pkt_len;
        if (pkt_len > max_pkt_len) max_pkt_len = pkt_len;

        if (forward) {
            fwd_pkts++;
            fwd_bytes += pkt_len;
        } else {
            bwd_pkts++;
            bwd_bytes += pkt_len;
        }

        if (syn) syn_count++;
        if (ack) ack_count++;
        if (fin) fin_count++;
        if (rst) rst_count++;
        if (psh) psh_count++;
    }

    uint64_t duration_us() const {
        return last_seen_ts_us - start_ts_us;
    }

    double mean_pkt_len() const {
        if (total_packets == 0) return 0.0;
        return static_cast<double>(sum_pkt_len) / total_packets;
    }
};
