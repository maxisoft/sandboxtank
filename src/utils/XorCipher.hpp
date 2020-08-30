#pragma once
#include <cstdio>
#include <cstdint>
#include <atomic>
#include "../hash/hash.hpp"

namespace maxisoft::utils
{
    namespace
    {
        constexpr uint64_t BaseKey = uint64_t(__COUNTER__) ^ maxisoft::hash::hash64(__COUNTER__) ^ maxisoft::hash::
        hash64(__TIMESTAMP__);
    }

    template <typename T, uint64_t BaseKey = static_cast<uint64_t>(BaseKey)>
    class XorCipher
    {
    public:
        using type = std::enable_if_t<std::is_integral_v<T>, T>;

        explicit XorCipher(const uint64_t key) : key_(key), counter_(0)
        {
        }

        type operator()(const type x)
        {
            return static_cast<type>((BaseKey ^ maxisoft::hash::hash64(++counter_) + key_) ^ x);
        }

    private:
        uint64_t key_;
        std::atomic_size_t counter_;
    };
}



