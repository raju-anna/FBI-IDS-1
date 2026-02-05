#include <iostream>
#include <thread>
#include <chrono>

#include "FlowTable.hpp"
#include "Flow.hpp"

int main() {
    std::cout << "==== FlowTable Test Start ====\n";

    // 1️⃣ Create FlowTable with 2-second idle timeout
    uint64_t idle_timeout_us = 2 * 1000 * 1000; // 2 seconds
    FlowTable table(idle_timeout_us);

    // 2️⃣ Create a FlowKey
    FlowKey key(
        "192.168.1.10",
        "192.168.1.20",
        12345,
        80,
        6   // TCP
    );

    // 3️⃣ Simulated timestamps (microseconds)
    uint64_t t0 = 1'000'000;
    uint64_t t1 = t0 + 500'000;     // +0.5s
    uint64_t t2 = t0 + 1'500'000;   // +1.5s
    uint64_t t3 = t0 + 3'000'000;   // +3.0s

    // 4️⃣ Insert flow
    Flow& f1 = table.get_or_create_flow(key, t0);
    std::cout << "Inserted flow at t0\n";
    std::cout << "Active flows: " << table.active_flow_count() << "\n";

    // 5️⃣ Reuse same flow (should NOT create new one)
    Flow& f2 = table.get_or_create_flow(key, t1);
    std::cout << "Reused flow at t1\n";
    std::cout << "Active flows: " << table.active_flow_count() << "\n";

    // Sanity check: same flow object
    if (&f1 == &f2) {
        std::cout << "✔ Same flow reused (correct)\n";
    } else {
        std::cout << "❌ Different flow created (BUG)\n";
    }

    // 6️⃣ Expire too early (should NOT expire)
    auto expired1 = table.expire_idle_flows(t2);
    std::cout << "Expired flows at t2: " << expired1.size() << "\n";
    std::cout << "Active flows: " << table.active_flow_count() << "\n";

    // 7️⃣ Expire after timeout (should expire)
    auto expired2 = table.expire_idle_flows(t3);
    std::cout << "Expired flows at t3: " << expired2.size() << "\n";
    std::cout << "Active flows: " << table.active_flow_count() << "\n";

    // 8️⃣ Validate expired flow stats
    if (!expired2.empty()) {
        const Flow& ef = expired2[0];
        std::cout << "Expired flow duration (us): "
                  << ef.duration_us() << "\n";
        std::cout << "Expired flow packets: "
                  << ef.total_packets << "\n";
    }

    std::cout << "==== FlowTable Test End ====\n";
    return 0;
}
