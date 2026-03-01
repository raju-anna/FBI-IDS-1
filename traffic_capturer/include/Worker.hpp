#pragma once
#include "Queue.hpp"
#include "FlowTable.hpp"
#include "Flow.hpp"
#include <atomic>
#include <cstdint>
#include <vector>

class Worker {
public:
    Worker(ThreadSafeQueue &q, int id,
           std::atomic<bool> &running_flag,
           FlowTable &flow_table);

    void operator()();

private:
    // Called every 1 000 packets to print and discard expired flows.
    // Takes Flow by non-const ref because FeatureExtractor::extract()
    // calls activity.finish() which mutates the flow.
    void print_expired(std::vector<Flow> &expired);

    ThreadSafeQueue   &queue_;
    int                id_;
    std::atomic<bool> &running_;
    FlowTable         &flow_table_;
    uint64_t           packet_count_{0};
};