#pragma once
#include "Queue.hpp"
#include "Packet_Parser.hpp"
#include <atomic>
#include "FlowTable.hpp"


class Worker {
public:
    Worker(ThreadSafeQueue &q, int id, std::atomic<bool> &running_flag, FlowTable &flow_table);
    void operator()();

private:
    ThreadSafeQueue &queue_;
    int id_;
    std::atomic<bool> &running_;
    FlowTable &flow_table_;

};
