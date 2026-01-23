#include "FeaturesDictBuilder.hpp"
#include <stdexcept>


std::unordered_map<std::string, float>
FeatureDictBuilder::build(const std::vector<float>& features) {

    if (features.size() != FEATURE_COUNT) {
        throw std::runtime_error(
            "FeatureDictBuilder: feature vector size mismatch"
        );
    }

    std::unordered_map<std::string, float> dict;
    dict.reserve(FEATURE_COUNT);

    dict["Flow Duration"]      = features[0];
    dict["Tot Fwd Pkts"]       = features[1];
    dict["Tot Bwd Pkts"]       = features[2];
    dict["Flow Byts/s"]        = features[3];
    dict["Flow Pkts/s"]        = features[4];
    dict["Fwd Pkt Len Mean"]   = features[5];
    dict["Bwd Pkt Len Mean"]   = features[6];
    dict["Pkt Len Std"]       = features[7];
    dict["Pkt Size Avg"]        = features[8];

    return dict;
}