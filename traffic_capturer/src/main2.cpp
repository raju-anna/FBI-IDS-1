#include <iostream>
#include <vector>
#include <thread>
#include <csignal>
#include <atomic>
#include <iomanip>

#include "Capture.hpp"
#include "Queue.hpp"
#include "Worker.hpp"
#include "FlowTable.hpp"
#include "Feature_Extractor.hpp"
#include "FeaturesDictBuilder.hpp"

static CaptureEngine    *g_cap     = nullptr;
static ThreadSafeQueue  *g_queue   = nullptr;
static std::atomic<bool> g_running{true};

void handle_sigint(int) {
    g_running.store(false);
    if (g_cap)   g_cap->break_loop();
    if (g_queue) g_queue->close();
}

// Print all remaining flows at shutdown — same table format as worker
static void drain_and_print(FlowTable &table)
{
    static const char* const NAMES[38] = {
        "Bwd Packet Length Std", "Bwd Packet Length Min", "Average Packet Size",
        "Init_Win_bytes_backward", "Bwd Packet Length Mean", "Init_Win_bytes_forward",
        "PSH Flag Count", "Bwd Packets/s", "Bwd Header Length", "Avg Bwd Segment Size",
        "Packet Length Mean", "Packet Length Variance", "Fwd Header Length",
        "Bwd Packet Length Max", "min_seg_size_forward", "ACK Flag Count",
        "act_data_pkt_fwd", "Fwd Header Length.1", "Packet Length Std",
        "Total Length of Fwd Packets", "Fwd PSH Flags", "Fwd Packet Length Max",
        "Fwd IAT Mean", "Total Fwd Packets", "Flow IAT Max", "Subflow Fwd Bytes",
        "Fwd IAT Max", "Total Length of Bwd Packets", "Max Packet Length",
        "Subflow Bwd Packets", "Min Packet Length", "Total Backward Packets",
        "Bwd IAT Total", "Idle Max", "Fwd IAT Min", "Fwd Packet Length Mean",
        "URG Flag Count", "Subflow Fwd Packets",
    };

    // Pass UINT64_MAX so every remaining flow looks idle and gets expired
    auto remaining = table.expire_idle_flows(UINT64_MAX);

    if (remaining.empty()) return;

    std::cout << "\n[+] Draining " << remaining.size()
              << " remaining flow(s) at shutdown...\n";

    for (Flow &f : remaining) {
        const auto features = FeatureExtractor::extract(f);

        std::cout << "\n══════════════ FLOW ══════════════\n"
                  << "  proto    = " << static_cast<int>(f.key.protocol) << "\n"
                  << "  fwd_pkts = " << f.volume.total_fwd_packets() << "\n"
                  << "  bwd_pkts = " << f.volume.total_bwd_packets() << "\n"
                  << "  bytes    = " << f.total_bytes() << "\n"
                  << "  dur_us   = " << f.duration_us() << "\n"
                  << "  ┌─────┬──────────────────────────────────┬─────────────────┐\n"
                  << "  │ Idx │ Feature Name                     │ Value           │\n"
                  << "  ├─────┼──────────────────────────────────┼─────────────────┤\n";

        for (size_t i = 0; i < features.size(); ++i) {
            std::cout << "  │ "
                      << std::setw(3) << std::right << i         << " │ "
                      << std::setw(32) << std::left  << NAMES[i]  << " │ "
                      << std::setw(15) << std::right
                      << std::fixed << std::setprecision(4) << features[i]
                      << " │\n";
        }

        std::cout << "  └─────┴──────────────────────────────────┴─────────────────┘\n";
    }
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        std::cerr << "Usage: sudo ./ids <interface>\n";
        return 1;
    }
    const std::string dev = argv[1];

    // 30-second idle flow timeout
    FlowTable       flow_table(30ULL * 1'000'000ULL);
    ThreadSafeQueue queue;
    g_queue = &queue;

    std::signal(SIGINT, handle_sigint);

    // Spawn workers — half of available cores, at least 1
    const unsigned int num_workers =
        std::max(1u, std::thread::hardware_concurrency() / 2);

    std::vector<std::thread> workers;
    workers.reserve(num_workers);
    for (unsigned int i = 0; i < num_workers; ++i)
        workers.emplace_back(Worker(queue, static_cast<int>(i), g_running, flow_table));

    // Open capture
    CaptureEngine cap;
    g_cap = &cap;

    std::string err;
    if (!cap.open_live(dev, 65535, true, 1000, &err)) {
        std::cerr << "pcap_open_live failed: " << err << "\n";
        queue.close();
        for (auto &t : workers) if (t.joinable()) t.join();
        return 1;
    }

    if (!cap.set_filter("ip and (tcp or udp)"))
        std::cerr << "[!] BPF filter failed: " << cap.get_error()
                  << " — continuing without filter\n";

    std::cout << "[+] Capture started on " << dev
              << " | workers=" << num_workers
              << " | timeout=30s\n"
              << "[+] Press Ctrl+C to stop and print remaining flows.\n";

    int ret = cap.loop(0, &queue);   // blocks until break_loop()

    if      (ret == -1) std::cerr << "pcap_loop error: " << cap.get_error() << "\n";
    else if (ret == -2) std::cout << "[*] Stopped by signal\n";
    else                std::cout << "[*] pcap_loop exited: " << ret << "\n";

    // Graceful shutdown
    queue.close();
    for (auto &t : workers) if (t.joinable()) t.join();
    cap.close();
    g_cap   = nullptr;
    g_queue = nullptr;

    // Print any flows that hadn't expired yet during capture
    drain_and_print(flow_table);

    std::cout << "\n[+] Shutdown complete."
              << " Dropped packets: " << queue.dropped_count() << "\n";
    return 0;
}