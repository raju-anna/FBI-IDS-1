#pragma once
#include <cstdint>
#include <limits>

// ---------------------------------------------------------------------------
// TCPStats — O(1) TCP-specific statistics.
//
// Tracks:
//   Flag counts  : PSH, ACK, SYN, FIN, URG (total and fwd-PSH separately)
//   Init windows : TCP window size of the FIRST fwd and FIRST bwd packet only
//   min_seg_size : minimum TCP header length seen in fwd direction (bytes)
//   act_data_pkt : fwd packets where payload_len > 0 (non-pure-ACK/SYN/FIN)
//
// TCP flags byte layout (RFC 793):
//   bit 0 = FIN  0x01
//   bit 1 = SYN  0x02
//   bit 2 = RST  0x04
//   bit 3 = PSH  0x08
//   bit 4 = ACK  0x10
//   bit 5 = URG  0x20
//
// Only called for TCP packets (ip_proto == 6).
// For UDP/ICMP flows all fields stay at their zero-initialised defaults.
// ---------------------------------------------------------------------------
struct TCPStats {

    // ── Flag counts ───────────────────────────────────────────────────────
    uint32_t psh_count{0};     // [6]  PSH Flag Count  (all directions)
    uint32_t ack_count{0};     // [15] ACK Flag Count
    uint32_t syn_count{0};     // SYN Flag Count
    uint32_t fin_count{0};     // FIN Flag Count
    uint32_t urg_count{0};     // [36] URG Flag Count
    uint32_t fwd_psh_count{0}; // [20] Fwd PSH Flags   (forward only)

    // ── Init window bytes ─────────────────────────────────────────────────
    // Captured once from the first fwd/bwd TCP packet. Never updated again.
    uint16_t init_win_fwd{0};  // [5]  Init_Win_bytes_forward
    uint16_t init_win_bwd{0};  // [3]  Init_Win_bytes_backward
    bool     fwd_win_set{false};
    bool     bwd_win_set{false};

    // ── min_seg_size_forward ──────────────────────────────────────────────
    // CICFlowMeter: minimum TCP header length (bytes) seen in fwd direction.
    // Initialised to max so first packet always becomes the minimum.
    uint16_t min_seg_size_fwd{std::numeric_limits<uint16_t>::max()};
    bool     fwd_tcp_seen{false}; // guard: stays max() until first fwd TCP pkt

    // ── act_data_pkt_fwd ─────────────────────────────────────────────────
    // Count of fwd packets that carry actual payload (payload_len > 0).
    // Pure SYN / ACK / FIN with no data do NOT increment this.
    uint32_t act_data_pkt_fwd{0}; // [16]

    // Update — called only for TCP packets, O(1)
    inline void update(uint8_t  tcp_flags,
                       uint16_t tcp_window,
                       uint16_t tcp_header_len,
                       uint32_t payload_len,
                       bool     forward) noexcept
    {
        // ── Flag counts ───────────────────────────────────────────────────
        if (tcp_flags & 0x08) { psh_count++; if (forward) fwd_psh_count++; }
        if (tcp_flags & 0x10)   ack_count++;
        if (tcp_flags & 0x02)   syn_count++;
        if (tcp_flags & 0x01)   fin_count++;
        if (tcp_flags & 0x20)   urg_count++;

        // ── Init window — captured once per direction ─────────────────────
        if (forward && !fwd_win_set) {
            init_win_fwd = tcp_window;
            fwd_win_set  = true;
        } else if (!forward && !bwd_win_set) {
            init_win_bwd = tcp_window;
            bwd_win_set  = true;
        }

        // ── min_seg_size_forward ──────────────────────────────────────────
        if (forward) {
            fwd_tcp_seen = true;
            if (tcp_header_len < min_seg_size_fwd)
                min_seg_size_fwd = tcp_header_len;
        }

        // ── act_data_pkt_fwd ─────────────────────────────────────────────
        if (forward && payload_len > 0)
            act_data_pkt_fwd++;
    }

    // ── Feature accessors (CIC exact names) ───────────────────────────────

    // [3]  Init_Win_bytes_backward
    uint16_t init_win_bytes_backward() const noexcept { return init_win_bwd; }

    // [5]  Init_Win_bytes_forward
    uint16_t init_win_bytes_forward()  const noexcept { return init_win_fwd; }

    // [6]  PSH Flag Count
    uint32_t psh_flag_count()          const noexcept { return psh_count;    }

    // [14] min_seg_size_forward — returns 0 if no fwd TCP packets seen
    uint16_t min_seg_size_forward()    const noexcept {
        return fwd_tcp_seen ? min_seg_size_fwd : 0;
    }

    // [15] ACK Flag Count
    uint32_t ack_flag_count()          const noexcept { return ack_count;    }

    // [16] act_data_pkt_fwd
    uint32_t act_data_pkts_fwd()       const noexcept { return act_data_pkt_fwd; }

    // [20] Fwd PSH Flags
    uint32_t fwd_psh_flags()           const noexcept { return fwd_psh_count; }

    // [36] URG Flag Count
    uint32_t urg_flag_count()          const noexcept { return urg_count;    }

    // Not in top 38 but tracked — SYN/FIN needed for flow lifecycle
    uint32_t syn_flag_count()          const noexcept { return syn_count;    }
    uint32_t fin_flag_count()          const noexcept { return fin_count;    }
};