#include "FlowTable.hpp"

FlowTable::FlowTable(uint64_t idle_timeout_us)
    : idle_timeout_us_(idle_timeout_us)
{
}

Flow& FlowTable::get_or_create_flow(const FlowKey& key, uint64_t ts_us) {
    std::lock_guard<std::mutex> lock(mtx_);

    auto it = flows_.find(key);
    if (it != flows_.end()) {
        return it->second;
    }

    auto res = flows_.emplace(key, Flow(key, ts_us));
    return res.first->second;
}

std::vector<Flow> FlowTable::expire_idle_flows(uint64_t current_ts_us) {
    std::vector<Flow> expired;
    std::lock_guard<std::mutex> lock(mtx_);

    for (auto it = flows_.begin(); it != flows_.end(); ) {
        uint64_t idle_time = current_ts_us - it->second.last_seen_ts_us;
        if (idle_time >= idle_timeout_us_) {
            expired.push_back(std::move(it->second));
            it = flows_.erase(it);
        } else {
            ++it;
        }
    }
    return expired;
}

size_t FlowTable::active_flow_count() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return flows_.size();
}

