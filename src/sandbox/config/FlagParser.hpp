#pragma once

#include <string>
#include <utility>
#include <vector>
#include <sstream>
#include <map>
#include <unordered_map>
#include <optional>
#include <nlohmann/json.hpp>
#include "../../windows_include.hpp"
#include "../../utils/StringUtils.hpp"
#include "../../hash/hash.hpp"

namespace maxisoft::sandbox::config
{
    template<typename FlagType = DWORD>
    class FlagParser
    {
        struct ignore_case_comp
        {
            bool operator()(const std::string &lhs, const std::string &rhs) const
            {
                return _stricmp(lhs.c_str(), rhs.c_str()) < 0;
            }
        };

        std::map<std::string, FlagType, ignore_case_comp> m_flag_map;
    public:
        template<class Container>
        FlagParser(const Container &flags, const std::string &prefix) noexcept : FlagParser(std::cbegin(flags),
                                                                                            std::cend(flags),
                                                                                            prefix),
        {

        }

        FlagParser(const std::initializer_list<std::pair<std::string, FlagType>> &initializer_list,
                   const std::string &prefix) noexcept: FlagParser(
                std::begin(initializer_list), std::end(initializer_list), prefix)
        {
        }

        template<class Begin, class End>
        FlagParser(Begin begin, End end, std::string prefix) noexcept : m_prefix(std::move(prefix))
        {

            const std::string &pfix = this->prefix();
            for (auto it = begin; it != end; ++it)
            {
                auto r = m_flag_map.insert_or_assign(it->first, it->second);
                if (r.second)
                {
                    if (!pfix.empty() && maxisoft::utils::findStringIC(r.first->first, pfix))
                    {
                        std::string cpy(r.first->first);
                        cpy.erase(0, pfix.size());
                        m_flag_map.insert_or_assign(cpy, it->second);
                    }
                }
                m_flag_map.insert_or_assign(to_string(it->second), it->second);
            }

        }

    public:
        [[nodiscard]] const std::string &prefix() const
        {
            return m_prefix;
        }

        template<class Begin, class End>
        std::vector<FlagType> parse(Begin begin, End end)
        {
            std::vector<FlagType> ret{};
            ret.reserve(std::distance(begin, end));
            for (auto it = begin; it != end; ++it)
            {
                if (auto res = parse(*it))
                {
                    ret.emplace_back(*res);
                }
            }
            return ret;
        }

        std::optional<FlagType> parse(const std::string &s) const
        {
            FlagType ret{};
            auto it = m_flag_map.find(s);
            if (it != m_flag_map.end())
            {
                return it->second;
            }
            return parse_numeric<FlagType>(s);
        }


    private:
        const std::string m_prefix;

        template<typename T>
        static inline typename std::enable_if<std::is_arithmetic<T>::value, std::string>::type to_string(T in)
        {
            return std::to_string(in);
        }

        [[maybe_unused]] static inline std::string to_string(const std::string &in)
        {
            return in;
        }

    private:
        template<class T = FlagType>
        static typename std::enable_if_t<std::is_arithmetic_v<T>, std::optional<FlagType>>
        parse_numeric(const std::string &s)
        {
            FlagType ret{};
            std::stringstream ss{};
            ss << s;
            try
            {
                ss >> ret;
                return ret;
            }
            catch (std::ios_base::failure &)
            {
                ss.str("");
                ss.clear();
            }
            ss << std::hex;
            ss << s;
            try
            {
                ss >> ret;
                return ret;
            }
            catch (std::ios_base::failure &)
            {
                ss.str("");
                ss.clear();
            }
            return {};
        }

        template<class T = FlagType>
        static typename std::enable_if_t<!std::is_arithmetic_v<T>, std::optional<FlagType>>
        parse_numeric(const std::string &s)
        {
            return {};
        }
    };
}



