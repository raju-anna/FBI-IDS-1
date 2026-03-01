#include "Worker.hpp"
#include "Packet_Parser.hpp"
#include "Feature_Extractor.hpp"
#include "Headers.hpp"
#include <iostream>
#include <iomanip>

Worker::Worker(ThreadSafeQueue &q, int id,
               std::atomic<bool> &running_flag,
               FlowTable &flow_table)
    : queue_(q), id_(id), running_(running_flag), flow_table_(flow_table)
{}

void Worker::operator()()
{
    ParsedPacket parsed;   // reused every iteration — no per-packet alloc

    while (running_.load()) {
        Packet pkt;
        if (!queue_.pop(pkt)) break;   // queue closed and empty

        // ── Parse ─────────────────────────────────────────────────────────
        if (!parse_packet(pkt, parsed)) continue;

        // ── Timestamp µs ──────────────────────────────────────────────────
        const uint64_t ts_us =
            static_cast<uint64_t>(pkt.ts.tv_sec)  * 1'000'000ULL +
            static_cast<uint64_t>(pkt.ts.tv_usec);

        // ── FlowKey ───────────────────────────────────────────────────────
        // Canonical key: lower IP first so both directions map to same flow.
        // If src < dst (numerically), src is "forward" by definition.
        bool forward;
        FlowKey key;
        if (parsed.src_ip < parsed.dst_ip ||
           (parsed.src_ip == parsed.dst_ip && parsed.src_port <= parsed.dst_port)) {
            key     = FlowKey(parsed.src_ip, parsed.dst_ip,
                              parsed.src_port, parsed.dst_port,
                              parsed.ip_proto);
            forward = true;
        } else {
            key     = FlowKey(parsed.dst_ip, parsed.src_ip,
                              parsed.dst_port, parsed.src_port,
                              parsed.ip_proto);
            forward = false;
        }

        // ── Build PacketMeta — single struct carries everything ───────────
        const PacketMeta meta = parsed.to_meta(ts_us, forward);

        // ── Update flow (create-or-update atomically under one lock) ──────
        flow_table_.update_flow(key, meta);

        // ── Expire idle flows every 1 000 packets (throttled) ─────────────
        if (++packet_count_ % 1000 == 0) {
            std::vector<Flow> expired = flow_table_.expire_idle_flows(ts_us);
            print_expired(expired);
        }
    }

    std::cout << "[W" << id_ << "] exiting\n";
}

void Worker::print_expired(std::vector<Flow> &expired)
{
    static const char* const NAMES[38] = {
        /*  0 */ "Bwd Packet Length Std",
        /*  1 */ "Bwd Packet Length Min",
        /*  2 */ "Average Packet Size",
        /*  3 */ "Init_Win_bytes_backward",
        /*  4 */ "Bwd Packet Length Mean",
        /*  5 */ "Init_Win_bytes_forward",
        /*  6 */ "PSH Flag Count",
        /*  7 */ "Bwd Packets/s",
        /*  8 */ "Bwd Header Length",
        /*  9 */ "Avg Bwd Segment Size",
        /* 10 */ "Packet Length Mean",
        /* 11 */ "Packet Length Variance",
        /* 12 */ "Fwd Header Length",
        /* 13 */ "Bwd Packet Length Max",
        /* 14 */ "min_seg_size_forward",
        /* 15 */ "ACK Flag Count",
        /* 16 */ "act_data_pkt_fwd",
        /* 17 */ "Fwd Header Length.1",
        /* 18 */ "Packet Length Std",
        /* 19 */ "Total Length of Fwd Packets",
        /* 20 */ "Fwd PSH Flags",
        /* 21 */ "Fwd Packet Length Max",
        /* 22 */ "Fwd IAT Mean",
        /* 23 */ "Total Fwd Packets",
        /* 24 */ "Flow IAT Max",
        /* 25 */ "Subflow Fwd Bytes",
        /* 26 */ "Fwd IAT Max",
        /* 27 */ "Total Length of Bwd Packets",
        /* 28 */ "Max Packet Length",
        /* 29 */ "Subflow Bwd Packets",
        /* 30 */ "Min Packet Length",
        /* 31 */ "Total Backward Packets",
        /* 32 */ "Bwd IAT Total",
        /* 33 */ "Idle Max",
        /* 34 */ "Fwd IAT Min",
        /* 35 */ "Fwd Packet Length Mean",
        /* 36 */ "URG Flag Count",
        /* 37 */ "Subflow Fwd Packets",
    };

    for (Flow &f : expired) {
        const auto features = FeatureExtractor::extract(f);

        // ── Flow header ───────────────────────────────────────────────────
        std::cout << "\n[W" << id_ << "] ══════════════ FLOW EXPIRED ══════════════\n"
                  << "  proto     = " << static_cast<int>(f.key.protocol) << "\n"
                  << "  fwd_pkts  = " << f.volume.total_fwd_packets() << "\n"
                  << "  bwd_pkts  = " << f.volume.total_bwd_packets() << "\n"
                  << "  bytes     = " << f.total_bytes() << "\n"
                  << "  dur_us    = " << f.duration_us() << "\n"
                  << "  ┌─────┬──────────────────────────────────┬─────────────────┐\n"
                  << "  │ Idx │ Feature Name                     │ Value           │\n"
                  << "  ├─────┼──────────────────────────────────┼─────────────────┤\n";

        for (size_t i = 0; i < features.size(); ++i) {
            std::cout << "  │ "
                      << std::setw(3) << std::right << i        << " │ "
                      << std::setw(32) << std::left  << NAMES[i] << " │ "
                      << std::setw(15) << std::right
                      << std::fixed << std::setprecision(4) << features[i]
                      << " │\n";
        }

        std::cout << "  └─────┴──────────────────────────────────┴─────────────────┘\n";
    }
}