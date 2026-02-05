#include "Feature_Extractor.hpp"

float FeatureExtractor::safe_div(float num, float denom){
    if(denom<=0.0f) return 0.0f;
    return num/denom;
}

std::vector<float> FeatureExtractor::extract(const Flow& flow){
    std::vector<float> features;
    features.reserve(9) ;   //initial features in v1

    float duration_sec = static_cast<float>(flow.duration_us()) / 1'000'000.0f;

    float total_packets = static_cast<float>(flow.total_packets);
    float total_bytes = static_cast<float>(flow.total_bytes);

    float fwd_pkts = static_cast<float>(flow.fwd_pkts);
    float bwd_pkts = static_cast<float>(flow.bwd_pkts);

    float fwd_bytes = static_cast<float>(flow.fwd_bytes);
    float bwd_bytes = static_cast<float>(flow.bwd_bytes);

    float flow_pkts_per_sec = safe_div(total_packets, duration_sec);
    float flow_bytes_per_sec = safe_div(total_bytes, duration_sec);

    float fwd_pkt_len_mean = safe_div(fwd_bytes, fwd_pkts);
    float bwd_pkt_len_mean = safe_div(bwd_bytes, bwd_pkts);

    float pkt_size_avg = safe_div(total_bytes, total_packets);

    float pkt_len_std = static_cast<float>(flow.packet_len_stddev());

    features.push_back(duration_sec);      
    features.push_back(fwd_pkts);         
    features.push_back(bwd_pkts);          
    features.push_back(flow_pkts_per_sec);    
    features.push_back(flow_bytes_per_sec);   
    features.push_back(fwd_pkt_len_mean);    
    features.push_back(bwd_pkt_len_mean);     
    features.push_back(pkt_len_std); 
    features.push_back(pkt_size_avg);
         

    return features;




}