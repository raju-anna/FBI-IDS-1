#include <iostream>
#include <thread>
#include <cassert>
#include <cmath>
#include <iomanip>

#include "FlowTable.hpp"
#include "Flow.hpp"
#include "PacketMeta.hpp"
#include "Feature_Extractor.hpp"
#include "FeaturesDictBuilder.hpp"

// ---------------------------------------------------------------------------
// Helper: build a minimal PacketMeta for test injection.
// tcp_flags: 0x02=SYN 0x10=ACK 0x01=FIN 0x08=PSH
// ---------------------------------------------------------------------------
static PacketMeta make_meta(uint64_t ts_us,
                             uint16_t ip_total_len,
                             bool     forward,
                             uint8_t  tcp_flags   = 0,
                             uint16_t tcp_window  = 0,
                             uint16_t tcp_hdr_len = 20,
                             uint32_t payload_len = 0,
                             uint16_t ip_hdr_len  = 20)
{
    PacketMeta m;
    m.ts_us          = ts_us;
    m.ip_total_len   = ip_total_len;
    m.ip_header_len  = ip_hdr_len;
    m.tcp_header_len = tcp_hdr_len;
    m.tcp_window     = tcp_window;
    m.tcp_flags      = tcp_flags;
    m.payload_len    = payload_len;
    m.forward        = forward;
    return m;
}

static FlowKey make_key(uint32_t src_ip, uint32_t dst_ip,
                         uint16_t sport,  uint16_t dport, uint8_t proto)
{
    return FlowKey(src_ip, dst_ip, sport, dport, proto);
}

// ── Test 1: basic create + expire ────────────────────────────────────────────
static void test_basic_expire()
{
    std::cout << "── Test 1: basic expire ──\n";

    FlowTable table(2'000'000ULL);   // 2-second idle timeout

    FlowKey  key = make_key(0xC0A8010A, 0xC0A80114, 12345, 80, 6);
    uint64_t t0  = 1'000'000;
    uint64_t t1  = t0 + 500'000;

    table.update_flow(key, make_meta(t0, 100, true,  0x02));  // SYN fwd
    table.update_flow(key, make_meta(t1, 200, false, 0x10));  // ACK bwd

    assert(table.active_flow_count() == 1);
    std::cout << "  active after 2 updates: " << table.active_flow_count() << " ✔\n";

    // t1 + 1.0s idle — should NOT expire (< 2s timeout)
    auto exp1 = table.expire_idle_flows(t1 + 1'000'000);
    assert(exp1.empty());
    std::cout << "  not expired at 1s idle: " << exp1.size() << " ✔\n";

    // t1 + 3.0s idle — SHOULD expire
    auto exp2 = table.expire_idle_flows(t1 + 3'000'000);
    assert(exp2.size() == 1);
    assert(table.active_flow_count() == 0);
    std::cout << "  expired at 3s idle: " << exp2.size() << " ✔\n";

    const Flow &f = exp2[0];
    std::cout << "  fwd_pkts=" << f.volume.total_fwd_packets()
              << " bwd_pkts=" << f.volume.total_bwd_packets()
              << " bytes="    << f.total_bytes()
              << " dur_us="   << f.duration_us() << "\n";

    assert(f.volume.total_fwd_packets() == 1);
    assert(f.volume.total_bwd_packets() == 1);
    assert(f.total_bytes()   == 300);
    assert(f.duration_us()   == 500'000);

    std::cout << "  Test 1 PASSED ✔\n\n";
}

// ── Test 2: multi-threaded concurrent updates ─────────────────────────────────
static void test_concurrent_updates()
{
    std::cout << "── Test 2: concurrent updates ──\n";

    FlowTable table(60'000'000ULL);

    FlowKey key_fwd = make_key(0xC0A80101, 0xC0A80102, 1111, 80, 6);
    FlowKey key_bwd = make_key(0xC0A80102, 0xC0A80101, 80, 1111, 6);

    constexpr int N      = 10000;
    uint64_t      base   = 1'000'000;

    auto worker = [&](FlowKey k) {
        for (int i = 0; i < N; ++i) {
            uint64_t ts = base + static_cast<uint64_t>(i) * 10;
            table.update_flow(k, make_meta(ts, 64, true, 0x10));
        }
    };

    std::thread t1(worker, key_fwd);
    std::thread t2(worker, key_bwd);
    std::thread t3(worker, key_fwd);   // contend on same key as t1
    t1.join(); t2.join(); t3.join();

    size_t active = table.active_flow_count();
    std::cout << "  active flows: " << active << " (expected 2)\n";
    assert(active == 2);
    std::cout << "  Test 2 PASSED ✔ (no crash, no data race)\n\n";
}

// ── Test 3: TCP flags correctly recorded in TCPStats ──────────────────────────
static void test_tcp_flags()
{
    std::cout << "── Test 3: TCP flags ──\n";

    FlowTable table(60'000'000ULL);
    FlowKey   key = make_key(0x01020304, 0x05060708, 5000, 443, 6);
    uint64_t  ts  = 1'000'000;

    // SYN fwd
    table.update_flow(key, make_meta(ts,       60,  true,  0x02, 65535, 20, 0));
    // ACK bwd
    table.update_flow(key, make_meta(ts+1000,  60,  false, 0x10, 65535, 20, 0));
    // ACK+PSH fwd with payload
    table.update_flow(key, make_meta(ts+2000,  500, true,  0x18, 65535, 20, 460));
    // FIN fwd
    table.update_flow(key, make_meta(ts+3000,  60,  true,  0x01, 65535, 20, 0));

    auto expired = table.expire_idle_flows(ts + 3000 + 60'000'000ULL);
    assert(expired.size() == 1);
    const Flow &f = expired[0];

    std::cout << "  syn=" << f.tcp.syn_flag_count()
              << " ack=" << f.tcp.ack_flag_count()
              << " fin=" << f.tcp.fin_flag_count()
              << " psh=" << f.tcp.psh_flag_count()
              << " act_data_fwd=" << f.tcp.act_data_pkts_fwd() << "\n";

    assert(f.tcp.syn_flag_count()   == 1);
    assert(f.tcp.ack_flag_count()   == 2);   // ACK bwd + ACK+PSH fwd
    assert(f.tcp.fin_flag_count()   == 1);
    assert(f.tcp.psh_flag_count()   == 1);
    assert(f.tcp.act_data_pkts_fwd() == 1);  // only the 460-byte packet
    assert(f.volume.total_fwd_packets() + f.volume.total_bwd_packets() == 4);

    std::cout << "  Test 3 PASSED ✔\n\n";
}

// ── Test 4: LengthStats Welford mean + stddev ─────────────────────────────────
static void test_length_stats()
{
    std::cout << "── Test 4: LengthStats mean + stddev ──\n";

    FlowTable table(60'000'000ULL);
    FlowKey   key = make_key(0xAABBCCDD, 0x11223344, 9000, 9001, 17);
    uint64_t  ts  = 1'000'000;

    // lengths: 100, 200, 300 → mean=200, population stddev≈81.65
    table.update_flow(key, make_meta(ts+0, 100, true));
    table.update_flow(key, make_meta(ts+1, 200, true));
    table.update_flow(key, make_meta(ts+2, 300, true));

    auto expired = table.expire_idle_flows(ts + 2 + 60'000'000ULL);
    assert(expired.size() == 1);
    const Flow &f = expired[0];

    double mean   = f.length.pkt_len_mean();
    double stddev = f.length.pkt_len_std();

    std::cout << "  mean="   << mean
              << " stddev=" << stddev
              << " (expected 200, ≈81.65)\n";

    assert(std::abs(mean   - 200.0) < 0.001);
    assert(std::abs(stddev -  81.65) < 0.1);
    std::cout << "  Test 4 PASSED ✔\n\n";
}

// ── Test 5: IATStats fwd inter-arrival times ──────────────────────────────────
static void test_iat_stats()
{
    std::cout << "── Test 5: IATStats ──\n";

    FlowTable table(60'000'000ULL);
    FlowKey   key = make_key(0x0A000001, 0x0A000002, 4000, 4001, 6);
    uint64_t  t0  = 1'000'000;

    // 3 fwd packets: gaps of 100µs and 200µs → fwd_iat mean=150µs
    table.update_flow(key, make_meta(t0,         60, true));
    table.update_flow(key, make_meta(t0+100,     60, true));
    table.update_flow(key, make_meta(t0+300,     60, true));
    // 1 bwd packet — no bwd IAT yet
    table.update_flow(key, make_meta(t0+400,     60, false));

    auto expired = table.expire_idle_flows(t0 + 400 + 60'000'000ULL);
    assert(expired.size() == 1);
    const Flow &f = expired[0];

    std::cout << "  fwd_iat_mean=" << f.iat.fwd_iat_mean()
              << " fwd_iat_max="  << f.iat.fwd_iat_max()
              << " fwd_iat_min="  << f.iat.fwd_iat_min()
              << " flow_iat_max=" << f.iat.flow_iat_max() << "\n";

    assert(std::abs(f.iat.fwd_iat_mean() - 150.0) < 0.001);
    assert(std::abs(f.iat.fwd_iat_max()  - 200.0) < 0.001);
    assert(std::abs(f.iat.fwd_iat_min()  - 100.0) < 0.001);
    std::cout << "  Test 5 PASSED ✔\n\n";
}

// ── Test 6: Full feature extraction (38 elements) ────────────────────────────
static void test_feature_extraction()
{
    std::cout << "── Test 6: Feature extraction ──\n";

    FlowTable table(60'000'000ULL);
    FlowKey   key = make_key(0xC0A80001, 0xC0A80002, 1234, 80, 6);
    uint64_t  ts  = 5'000'000;

    // A realistic mini-flow: SYN, data, FIN
    table.update_flow(key, make_meta(ts,          60,   true,  0x02, 65535, 20, 0));    // SYN
    table.update_flow(key, make_meta(ts+1000,     60,   false, 0x12, 8192,  20, 0));    // SYN-ACK
    table.update_flow(key, make_meta(ts+2000,     60,   true,  0x10, 65535, 20, 0));    // ACK
    table.update_flow(key, make_meta(ts+3000,     1500, true,  0x18, 65535, 20, 1440)); // PSH+ACK
    table.update_flow(key, make_meta(ts+4000,     1500, false, 0x18, 8192,  20, 1440)); // PSH+ACK
    table.update_flow(key, make_meta(ts+5000,     60,   true,  0x11, 65535, 20, 0));    // FIN+ACK
    table.update_flow(key, make_meta(ts+6000,     60,   false, 0x11, 8192,  20, 0));    // FIN+ACK

    auto expired = table.expire_idle_flows(ts + 6000 + 60'000'000ULL);
    assert(expired.size() == 1);

    auto features = FeatureExtractor::extract(expired[0]);
    assert(features.size() == FeatureExtractor::FEATURE_COUNT);

    auto dict = FeatureDictBuilder::build(features);
    assert(dict.size() == FeatureDictBuilder::FEATURE_COUNT);

    std::cout << "  Feature count: " << features.size() << " ✔\n\n";

    // CIC feature names in index order — matches FeaturesDictBuilder exactly
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

    std::cout << "  ┌─────┬──────────────────────────────────┬─────────────────┐\n";
    std::cout << "  │ Idx │ Feature Name                     │ Value           │\n";
    std::cout << "  ├─────┼──────────────────────────────────┼─────────────────┤\n";
    for (size_t i = 0; i < 38; ++i) {
        std::cout << "  │ "
                  << std::setw(3) << std::right << i << " │ "
                  << std::setw(32) << std::left  << NAMES[i] << " │ "
                  << std::setw(15) << std::right << std::fixed << std::setprecision(4) << features[i]
                  << " │\n";
    }
    std::cout << "  └─────┴──────────────────────────────────┴─────────────────┘\n\n";

    // Sanity assertions — run after print so table always displays
    assert(dict.at("Total Fwd Packets")       == 4.0f);
    assert(dict.at("Total Backward Packets")  == 3.0f);
    assert(dict.at("PSH Flag Count")          == 2.0f);
    assert(dict.at("ACK Flag Count")          == 6.0f);
    assert(dict.at("Init_Win_bytes_forward")  == 65535.0f);
    assert(dict.at("Init_Win_bytes_backward") == 8192.0f);
    assert(dict.at("act_data_pkt_fwd")        == 1.0f);

    std::cout << "  Test 6 PASSED ✔\n\n";
}

int main()
{
    std::cout << "==== FlowTable + Feature Extraction Test Suite ====\n\n";
    test_basic_expire();
    test_concurrent_updates();
    test_tcp_flags();
    test_length_stats();
    test_iat_stats();
    test_feature_extraction();
    std::cout << "==== All tests PASSED ====\n";
    return 0;
}