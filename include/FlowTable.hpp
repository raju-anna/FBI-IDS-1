#pragma once

#include "Flow.hpp"
#include <unordered_map>
#include <vector>
#include <mutex>
#include <cstdint>

class FlowTable {
public:
    explicit FlowTable(uint64_t idle_timeout_us);

    Flow& get_or_create_flow(const FlowKey& key, uint64_t ts_us);

    std::vector<Flow> expire_idle_flows(uint64_t current_ts_us);

    size_t active_flow_count() const;

private:
    std::unordered_map<FlowKey, Flow, FlowKeyHash> flows_;
    uint64_t idle_timeout_us_;
    mutable std::mutex mtx_;
};
