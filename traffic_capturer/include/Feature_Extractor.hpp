#pragma once
#include "Flow.hpp"
#include <vector>
#include <cmath>
#include <algorithm>

// ---------------------------------------------------------------------------
// FeatureExtractor — produces the CICFlowMeter top-38 feature vector.
//
// ┌─────┬──────────────────────────────────┬──────────────────────────────────────────────────┐
// │ Idx │ CIC Feature Name                 │ Source                                           │
// ├─────┼──────────────────────────────────┼──────────────────────────────────────────────────┤
// │  0  │ Bwd Packet Length Std            │ flow.length.bwd_pkt_len_std()                    │
// │  1  │ Bwd Packet Length Min            │ flow.length.bwd_pkt_len_min()                    │
// │  2  │ Average Packet Size              │ total_bytes / total_packets  (computed here)      │
// │  3  │ Init_Win_bytes_backward          │ flow.tcp.init_win_bytes_backward()               │
// │  4  │ Bwd Packet Length Mean           │ flow.length.bwd_pkt_len_mean()                   │
// │  5  │ Init_Win_bytes_forward           │ flow.tcp.init_win_bytes_forward()                │
// │  6  │ PSH Flag Count                   │ flow.tcp.psh_flag_count()                        │
// │  7  │ Bwd Packets/s                    │ volume.total_bwd / duration_s  (computed here)   │
// │  8  │ Bwd Header Length                │ flow.headers.bwd_header_length()                 │
// │  9  │ Avg Bwd Segment Size             │ flow.length.bwd_pkt_len_mean()  [same as [4]]    │
// │ 10  │ Packet Length Mean               │ flow.length.pkt_len_mean()                       │
// │ 11  │ Packet Length Variance           │ flow.length.pkt_len_variance()                   │
// │ 12  │ Fwd Header Length                │ flow.headers.fwd_header_length()                 │
// │ 13  │ Bwd Packet Length Max            │ flow.length.bwd_pkt_len_max()                    │
// │ 14  │ min_seg_size_forward             │ flow.tcp.min_seg_size_forward()                  │
// │ 15  │ ACK Flag Count                   │ flow.tcp.ack_flag_count()                        │
// │ 16  │ act_data_pkt_fwd                 │ flow.tcp.act_data_pkts_fwd()                     │
// │ 17  │ Fwd Header Length.1              │ flow.headers.fwd_header_length()  [dup of [12]]  │
// │ 18  │ Packet Length Std                │ flow.length.pkt_len_std()                        │
// │ 19  │ Total Length of Fwd Packets      │ flow.length.total_len_fwd()                      │
// │ 20  │ Fwd PSH Flags                    │ flow.tcp.fwd_psh_flags()                         │
// │ 21  │ Fwd Packet Length Max            │ flow.length.fwd_pkt_len_max()                    │
// │ 22  │ Fwd IAT Mean                     │ flow.iat.fwd_iat_mean()                          │
// │ 23  │ Total Fwd Packets                │ flow.volume.total_fwd_packets()                  │
// │ 24  │ Flow IAT Max                     │ flow.iat.flow_iat_max()                          │
// │ 25  │ Subflow Fwd Bytes                │ flow.length.total_len_fwd()  [same as [19]]      │
// │ 26  │ Fwd IAT Max                      │ flow.iat.fwd_iat_max()                           │
// │ 27  │ Total Length of Bwd Packets      │ flow.length.total_len_bwd()                      │
// │ 28  │ Max Packet Length                │ flow.length.max_pkt_len()                        │
// │ 29  │ Subflow Bwd Packets              │ flow.volume.total_bwd_packets()  [same as [31]]  │
// │ 30  │ Min Packet Length                │ flow.length.min_pkt_len()                        │
// │ 31  │ Total Backward Packets           │ flow.volume.total_bwd_packets()                  │
// │ 32  │ Bwd IAT Total                    │ flow.iat.bwd_iat_total_val()                     │
// │ 33  │ Idle Max                         │ flow.activity.idle_max()                         │
// │ 34  │ Fwd IAT Min                      │ flow.iat.fwd_iat_min()                           │
// │ 35  │ Fwd Packet Length Mean           │ flow.length.fwd_pkt_len_mean()                   │
// │ 36  │ URG Flag Count                   │ flow.tcp.urg_flag_count()                        │
// │ 37  │ Subflow Fwd Packets              │ flow.volume.total_fwd_packets()  [same as [23]]  │
// └─────┴──────────────────────────────────┴──────────────────────────────────────────────────┘
//
// Conversions:
//   - All µs timestamps stay as-is (float cast).
//   - Rates are computed in packets/second using duration_s = duration_us / 1e6.
//   - safe_div() guards all divisions against zero denominator → 0.0f.
//   - activity.finish() is called here; never call it externally.
// ---------------------------------------------------------------------------

class FeatureExtractor {
public:

    static constexpr size_t FEATURE_COUNT = 38;

    // extract() — call once per expired flow.
    // Calls activity.finish() internally; do not call it before this.
    // Returns a vector of exactly FEATURE_COUNT floats.
    static std::vector<float> extract(Flow &flow)
    {
        // Finalize the last active burst before reading idle/active features
        flow.activity.finish();

        std::vector<float> f;
        f.reserve(FEATURE_COUNT);

        // ── Helpers ───────────────────────────────────────────────────────
        const double dur_us  = static_cast<double>(flow.duration_us());
        const double dur_s   = dur_us / 1'000'000.0;   // for rate features
        const double tot_pkt = static_cast<double>(flow.volume.total_pkt_count());
        const double tot_byt = static_cast<double>(flow.total_bytes());
        const double bwd_pkt = static_cast<double>(flow.volume.total_bwd_packets());

        // ── [0]  Bwd Packet Length Std ────────────────────────────────────
        f.push_back(static_cast<float>(flow.length.bwd_pkt_len_std()));

        // ── [1]  Bwd Packet Length Min ────────────────────────────────────
        f.push_back(static_cast<float>(flow.length.bwd_pkt_len_min()));

        // ── [2]  Average Packet Size ──────────────────────────────────────
        // CIC: total_bytes / total_packets (NOT running mean)
        f.push_back(safe_div(static_cast<float>(tot_byt),
                             static_cast<float>(tot_pkt)));

        // ── [3]  Init_Win_bytes_backward ──────────────────────────────────
        f.push_back(static_cast<float>(flow.tcp.init_win_bytes_backward()));

        // ── [4]  Bwd Packet Length Mean ───────────────────────────────────
        f.push_back(static_cast<float>(flow.length.bwd_pkt_len_mean()));

        // ── [5]  Init_Win_bytes_forward ───────────────────────────────────
        f.push_back(static_cast<float>(flow.tcp.init_win_bytes_forward()));

        // ── [6]  PSH Flag Count ───────────────────────────────────────────
        f.push_back(static_cast<float>(flow.tcp.psh_flag_count()));

        // ── [7]  Bwd Packets/s ────────────────────────────────────────────
        // CIC: total_bwd_packets / duration_seconds
        f.push_back(safe_div(static_cast<float>(bwd_pkt),
                             static_cast<float>(dur_s)));

        // ── [8]  Bwd Header Length ────────────────────────────────────────
        f.push_back(static_cast<float>(flow.headers.bwd_header_length()));

        // ── [9]  Avg Bwd Segment Size ─────────────────────────────────────
        // CIC: exact duplicate of Bwd Packet Length Mean
        f.push_back(static_cast<float>(flow.length.bwd_pkt_len_mean()));

        // ── [10] Packet Length Mean ───────────────────────────────────────
        f.push_back(static_cast<float>(flow.length.pkt_len_mean()));

        // ── [11] Packet Length Variance ───────────────────────────────────
        f.push_back(static_cast<float>(flow.length.pkt_len_variance()));

        // ── [12] Fwd Header Length ────────────────────────────────────────
        f.push_back(static_cast<float>(flow.headers.fwd_header_length()));

        // ── [13] Bwd Packet Length Max ────────────────────────────────────
        f.push_back(static_cast<float>(flow.length.bwd_pkt_len_max()));

        // ── [14] min_seg_size_forward ─────────────────────────────────────
        f.push_back(static_cast<float>(flow.tcp.min_seg_size_forward()));

        // ── [15] ACK Flag Count ───────────────────────────────────────────
        f.push_back(static_cast<float>(flow.tcp.ack_flag_count()));

        // ── [16] act_data_pkt_fwd ─────────────────────────────────────────
        f.push_back(static_cast<float>(flow.tcp.act_data_pkts_fwd()));

        // ── [17] Fwd Header Length.1 ──────────────────────────────────────
        // CIC CSV artifact: exact duplicate of [12]
        f.push_back(static_cast<float>(flow.headers.fwd_header_length()));

        // ── [18] Packet Length Std ────────────────────────────────────────
        f.push_back(static_cast<float>(flow.length.pkt_len_std()));

        // ── [19] Total Length of Fwd Packets ─────────────────────────────
        f.push_back(static_cast<float>(flow.length.total_len_fwd()));

        // ── [20] Fwd PSH Flags ────────────────────────────────────────────
        f.push_back(static_cast<float>(flow.tcp.fwd_psh_flags()));

        // ── [21] Fwd Packet Length Max ────────────────────────────────────
        f.push_back(static_cast<float>(flow.length.fwd_pkt_len_max()));

        // ── [22] Fwd IAT Mean ─────────────────────────────────────────────
        f.push_back(static_cast<float>(flow.iat.fwd_iat_mean()));

        // ── [23] Total Fwd Packets ────────────────────────────────────────
        f.push_back(static_cast<float>(flow.volume.total_fwd_packets()));

        // ── [24] Flow IAT Max ─────────────────────────────────────────────
        f.push_back(static_cast<float>(flow.iat.flow_iat_max()));

        // ── [25] Subflow Fwd Bytes ────────────────────────────────────────
        // CIC: exact duplicate of Total Length of Fwd Packets [19]
        f.push_back(static_cast<float>(flow.length.total_len_fwd()));

        // ── [26] Fwd IAT Max ──────────────────────────────────────────────
        f.push_back(static_cast<float>(flow.iat.fwd_iat_max()));

        // ── [27] Total Length of Bwd Packets ─────────────────────────────
        f.push_back(static_cast<float>(flow.length.total_len_bwd()));

        // ── [28] Max Packet Length ────────────────────────────────────────
        f.push_back(static_cast<float>(flow.length.max_pkt_len()));

        // ── [29] Subflow Bwd Packets ──────────────────────────────────────
        // CIC: exact duplicate of Total Backward Packets [31]
        f.push_back(static_cast<float>(flow.volume.total_bwd_packets()));

        // ── [30] Min Packet Length ────────────────────────────────────────
        f.push_back(static_cast<float>(flow.length.min_pkt_len()));

        // ── [31] Total Backward Packets ───────────────────────────────────
        f.push_back(static_cast<float>(flow.volume.total_bwd_packets()));

        // ── [32] Bwd IAT Total ────────────────────────────────────────────
        f.push_back(static_cast<float>(flow.iat.bwd_iat_total_val()));

        // ── [33] Idle Max ─────────────────────────────────────────────────
        f.push_back(static_cast<float>(flow.activity.idle_max()));

        // ── [34] Fwd IAT Min ──────────────────────────────────────────────
        f.push_back(static_cast<float>(flow.iat.fwd_iat_min()));

        // ── [35] Fwd Packet Length Mean ───────────────────────────────────
        f.push_back(static_cast<float>(flow.length.fwd_pkt_len_mean()));

        // ── [36] URG Flag Count ───────────────────────────────────────────
        f.push_back(static_cast<float>(flow.tcp.urg_flag_count()));

        // ── [37] Subflow Fwd Packets ──────────────────────────────────────
        // CIC: exact duplicate of Total Fwd Packets [23]
        f.push_back(static_cast<float>(flow.volume.total_fwd_packets()));

        return f;   // exactly FEATURE_COUNT elements
    }

private:
    // Divide safely; returns 0.0f when denominator is zero or near-zero.
    static inline float safe_div(float num, float denom) noexcept {
        return (std::abs(denom) < 1e-9f) ? 0.0f : num / denom;
    }
};