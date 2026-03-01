#pragma once
#include <unordered_map>
#include <vector>
#include <string>
#include <stdexcept>

// ---------------------------------------------------------------------------
// FeatureDictBuilder — maps the flat 38-element feature vector to the exact
// CICFlowMeter column names used in CICIDS2017/2018 CSV datasets.
//
// build() throws std::runtime_error if features.size() != FEATURE_COUNT.
// The returned map can be JSON-serialised, logged, or fed to a model that
// expects named inputs.
//
// Column names are verbatim from CICFlowMeter — including the deliberate
// duplicate "Fwd Header Length.1" (index 17) and the Subflow aliases
// (indices 25, 29, 37) which are identical values under different names.
// ---------------------------------------------------------------------------
class FeatureDictBuilder {
public:

    static constexpr size_t FEATURE_COUNT = 38;

    static std::unordered_map<std::string, float>
    build(const std::vector<float> &features)
    {
        if (features.size() != FEATURE_COUNT) {
            throw std::runtime_error(
                "FeatureDictBuilder::build — expected " +
                std::to_string(FEATURE_COUNT) +
                " features, got " +
                std::to_string(features.size()));
        }

        // Column names in index order — exactly matching CICFlowMeter CSVs
        static const char* const NAMES[FEATURE_COUNT] = {
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
            /* 17 */ "Fwd Header Length.1",    // CIC CSV duplicate of [12]
            /* 18 */ "Packet Length Std",
            /* 19 */ "Total Length of Fwd Packets",
            /* 20 */ "Fwd PSH Flags",
            /* 21 */ "Fwd Packet Length Max",
            /* 22 */ "Fwd IAT Mean",
            /* 23 */ "Total Fwd Packets",
            /* 24 */ "Flow IAT Max",
            /* 25 */ "Subflow Fwd Bytes",      // CIC alias for [19]
            /* 26 */ "Fwd IAT Max",
            /* 27 */ "Total Length of Bwd Packets",
            /* 28 */ "Max Packet Length",
            /* 29 */ "Subflow Bwd Packets",    // CIC alias for [31]
            /* 30 */ "Min Packet Length",
            /* 31 */ "Total Backward Packets",
            /* 32 */ "Bwd IAT Total",
            /* 33 */ "Idle Max",
            /* 34 */ "Fwd IAT Min",
            /* 35 */ "Fwd Packet Length Mean",
            /* 36 */ "URG Flag Count",
            /* 37 */ "Subflow Fwd Packets",    // CIC alias for [23]
        };

        std::unordered_map<std::string, float> dict;
        dict.reserve(FEATURE_COUNT);
        for (size_t i = 0; i < FEATURE_COUNT; ++i) {
            dict.emplace(NAMES[i], features[i]);
        }
        return dict;
    }
};