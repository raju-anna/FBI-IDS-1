#pragma once

#include <Flow.hpp>
#include <vector>

class FeatureExtractor{

    public :
        static std::vector<float> extract(const Flow& flow);

    private :
        static float safe_div(float num, float denom);
};