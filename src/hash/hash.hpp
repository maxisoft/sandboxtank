#pragma once

#include "crc.hpp"

namespace maxisoft::hash
{
    template<typename T, size_t Size>
    constexpr uint32_t inline hash32(const T(&s)[Size])
    {
        uint32_t crc = 0;
        if (Size <= 0) return crc;
        for (size_t i = 0; i < Size; ++i)
        {
            crc = crc_table[static_cast<uint8_t>(s[i] ^ ((crc >> 24) & 0xff))] ^ (crc << 8);
        }
        return crc;
    }

    template<typename T, size_t Size>
    constexpr uint64_t inline hash64(const T(&s)[Size])
    {
        uint64_t crc = 0;
        if (Size <= 0) return crc;
        for (size_t i = 0; i < Size - 1; ++i)
        {
            for (size_t j = 0; j < sizeof(T); ++j)
            {
                const auto value = static_cast<char>((static_cast<uint64_t>(s[i]) >> (j * 8)) & 0xFF);
                crc = hash64_tab[static_cast<uint8_t>(static_cast<uint8_t>(crc) ^ value)] ^ (crc >> 8);
            }
        }
        return crc;
    }

    template<typename T, size_t Size>
    constexpr uint64_t inline hash64(const std::array<T, Size> &s)
    {
        uint64_t crc = 0;
        for (size_t i = 0; i < Size; ++i)
        {
            for (size_t j = 0; j < sizeof(T); ++j)
            {
                const auto value = static_cast<char>((static_cast<uint64_t>(s[i]) >> (j * 8)) & 0xFF);
                crc = hash64_tab[static_cast<uint8_t>(static_cast<uint8_t>(crc) ^ value)] ^ (crc >> 8);
            }
        }
        return crc;
    }

    constexpr uint64_t inline hash64(const char *s, const size_t len)
    {
        uint64_t crc = 0;
        for (size_t i = 0; i < len; ++i)
        {
            crc = hash64_tab[static_cast<uint8_t>(static_cast<uint8_t>(crc) ^ s[i])] ^ (crc >> 8);
        }
        return crc;
    }

    constexpr uint64_t inline hash64(const char *s)
    {
        uint64_t crc = 0;
        for (size_t i = 0; s[i] != 0; ++i)
        {
            crc = hash64_tab[static_cast<uint8_t>(static_cast<uint8_t>(crc) ^ s[i])] ^ (crc >> 8);
        }
        return crc;
    }

    template<class T>
    typename std::enable_if<sizeof(T) != 0, uint64_t>::type inline hash64(const T *s, const size_t len)
    {
        return hash64(reinterpret_cast<char *>(s), len * sizeof(T));
    }

    template<typename T>
    constexpr typename std::enable_if<std::is_arithmetic<T>::value &&
                                      !std::is_floating_point<T>::value,
            uint64_t>::type
    inline hash64(const T s)
    {
        uint64_t crc = 0;
        for (size_t i = 0; i < sizeof(T); ++i)
        {
            const auto value = static_cast<char>((static_cast<uint64_t>(s) >> (i * 8)) & 0xFF);
            crc = hash64_tab[static_cast<uint8_t>(static_cast<uint8_t>(crc) ^ value)] ^ (crc >> 8);
        }
        return crc;
    }

    template<typename T>
    constexpr typename std::enable_if<std::is_floating_point<T>::value,
            uint64_t>::type
    inline hash64(const T s)
    {
        auto intval = static_cast<int64_t>(s);
        auto reminder = s - intval;
        uint64_t crc = hash64(intval);
        if (reminder != T(0))
        {
            const auto sign = reminder < 0 ? -1 : 1;
            reminder *= sign;
            while (reminder < 1)
            {
                reminder *= 10;
            }
            for (size_t i = 0; i < sizeof(uint64_t); ++i)
            {
                const auto value = static_cast<char>((static_cast<uint64_t>(reminder) >> (i * 8)) & 0xFF);
                crc = hash64_tab[static_cast<uint8_t>(static_cast<uint8_t>(crc) ^ value)] ^ (crc >> 8);
            }
        }
        return crc;
    }

    static_assert(hash64(0L) == 0);
    static_assert(hash64(0) != hash64(1));
    static_assert(hash64(1) != hash64(2));
    static_assert(hash64(0.0f) == 0);
    static_assert(hash64(-1.0f) != 0);
// This doesn't take into account the nul char
#define COMPILE_TIME_CRC32_STR(str) (maxisoft::hash::hash32((str)))
#define COMPILE_TIME_CRC64_STR(str) (maxisoft::hash::hash64((str)))
}

