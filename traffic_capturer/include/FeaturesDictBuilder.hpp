#pragma once

#include <unordered_map>
#include <vector>
#include <string>

class FeatureDictBuilder{

    public:

    static std::unordered_map<std::string, float> build(const std::vector<float> &features);

    static constexpr size_t FEATURE_COUNT = 9;
};