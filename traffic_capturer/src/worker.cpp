#include "Worker.hpp"
#include "Packet_Parser.hpp"
#include "Feature_Extractor.hpp"
#include "FeaturesDictBuilder.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>

static inline bool is_printable_ascii(char c)
{
    unsigned char uc = static_cast<unsigned char>(c);
    return (uc >= 0x20 && uc <= 0x7E); // basic printable range
}

// helper: sanitize snippet (replace non-printable with '.')
static std::string sanitize_snippet(const std::string &s)
{
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s)
    {
        if (c >= 0x20 && c <= 0x7E)
            out.push_back(static_cast<char>(c));
        else
            out.push_back('.');
    }
    return out;
}

Worker::Worker(ThreadSafeQueue &q, int id, std::atomic<bool> &running_flag, FlowTable &flow_table)
    : queue_(q), id_(id), running_(running_flag), flow_table_(flow_table) {}

void Worker::operator()()
{
    while (running_.load())
    {
        Packet pkt;
        bool ok = queue_.pop(pkt);
        if (!ok)
            break;
        auto parsed_opt = parse_packet(pkt);
        if (!parsed_opt)
        {
            // print short hex summary for non-ip or errors
            // std::ostringstream os;
            // os << "[W" << id_ << "] ts=" << pkt.ts.tv_sec << "." << std::setw(6) << std::setfill('0') << pkt.ts.tv_usec
            //    << " caplen=" << pkt.caplen << " first=";
            // size_t n = std::min<size_t>(pkt.data.size(), 12);
            // for (size_t i = 0; i < n; ++i)
            // {
            //     os << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(pkt.data[i]);
            //     if (i + 1 < n)
            //         os << " ";
            // }
            // os << std::dec;
            // std::cout << os.str() << std::endl;
            continue;
        }

        // auto &p = *parsed_opt;

        // if (p.payload == nullptr || p.payload_len == 0) {
        //     // nothing to match
        //     continue;
        // }

        // std::string payload(reinterpret_cast<const char*>(p.payload), p.payload_len);

        // const size_t MAX_SNIPPET = 80;
        // std::string snippet;
        // if (payload.size() == 0) {
        //     snippet = "";
        // } else if (payload.size() <= MAX_SNIPPET) {
        //     snippet = sanitize_snippet(payload);
        // } else {
        //     // take the first MAX_SNIPPET bytes (you could center around match offset later)
        //     snippet = sanitize_snippet(payload.substr(0, MAX_SNIPPET));
        // }

        // std::cout << "[W" << id_ << "] "
        //     << "src=" << p.src_ip << " dst=" << p.dst_ip
        //     << " sport=" << p.src_port << " dport=" << p.dst_port
        //     << " payload_len=" << p.payload_len
        //     << std::endl;

        // std::cout << "[W" << id_ << "] " ;
        // std::cout << "ETH type=0x" << std::hex << p.ethertype << std::dec;
        // if (p.is_ipv4) {
        //     std::cout << " IPv4 src=" << p.src_ip << " dst=" << p.dst_ip << " proto=" << int(p.ip_proto);
        //     if (p.is_tcp) {
        //         std::cout << " TCP " << p.src_port << "->" << p.dst_port << " payload=" << p.payload_len;
        //     } else if (p.is_udp) {
        //         std::cout << " UDP " << p.src_port << "->" << p.dst_port << " payload=" << p.payload_len;
        //     }
        // }

        const ParsedPacket &parsed = parsed_opt.value();

        // 2) Build FlowKey
        FlowKey key(
            parsed.src_ip,
            parsed.dst_ip,
            parsed.src_port,
            parsed.dst_port,
            parsed.ip_proto);

        // 3) Timestamp in microseconds
        uint64_t ts_us =
            static_cast<uint64_t>(pkt.ts.tv_sec) * 1000000ULL +
            static_cast<uint64_t>(pkt.ts.tv_usec);

        // 4) Get or create flow
        Flow &flow = flow_table_.get_or_create_flow(key, ts_us);

        // 5) Determine direction
        bool forward =
            (parsed.src_ip == flow.key.src_ip) &&
            (parsed.src_port == flow.key.src_port);

        // 6) Extract packet metadata
        uint32_t pkt_len = pkt.caplen;

        bool syn = false, ack = false, fin = false, rst = false, psh = false;
        // if (parsed.tcp != nullptr)
        // {
        //     uint8_t flags = parsed.tcp->th_flags;
        //     syn = flags & TH_SYN;
        //     ack = flags & TH_ACK;
        //     fin = flags & TH_FIN;
        //     rst = flags & TH_RST;
        //     psh = flags & TH_PUSH;
        // }

        // 7) Update flow
        flow.update(
            ts_us,
            pkt_len,
            forward,
            syn,
            ack,
            fin,
            rst,
            psh);

        // 8) Expire idle flows
        auto expired_flows = flow_table_.expire_idle_flows(ts_us);

        // 9) TEMP: Print expired flow summary
        for (const auto &f : expired_flows)
        {
            // std::cout
            //     << "[FLOW EXPIRED] "
            //     << f.key.src_ip << ":" << f.key.src_port
            //     << " -> "
            //     << f.key.dst_ip << ":" << f.key.dst_port
            //     << " proto=" << static_cast<int>(f.key.protocol)
            //     << " duration_us=" << f.duration_us()
            //     << " packets=" << f.total_packets
            //     << " bytes=" << f.total_bytes
            //     << std::endl;

            auto features = FeatureExtractor::extract(f);
            auto dict = FeatureDictBuilder::build(features);

            std::cout << "[FEATURES] ";

            for (const auto &[k, v] : dict)
            {
                std::cout << k << " = " << v << std::endl;
            }

            
            // for (float v : features)
            // {
            //     std::cout << v << " ";
            // }
            // std::cout << std::endl;
        }

        std::cout << std::endl;
    }
    // worker exiting
}
