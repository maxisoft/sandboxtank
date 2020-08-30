#pragma once

#include <string>
#include <locale>

#ifdef _WIN32

#include <stringapiset.h>

#else
#include <codecvt>
#endif

#include <cassert>
#include <algorithm>

namespace maxisoft::utils
{
    namespace details
    {
        static std::locale loc;
#ifndef _WIN32

        static std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converterX;
#endif
        constexpr UINT default_codepage = CP_ACP;
    }

    inline std::wstring s2ws(const std::string &str, const UINT codepage = details::default_codepage)
    {
#ifdef _WIN32
        const std::string::size_type limit = (std::numeric_limits<int>::max)();
        assert(str.size() < limit);
        const int ansiByteSize = static_cast<int>(str.size());
        const auto wideCharSize = ::MultiByteToWideChar(codepage, MB_ERR_INVALID_CHARS, str.c_str(), ansiByteSize,
                                                        nullptr, 0);

        std::wstring returnValue(wideCharSize, L'\0');
        const auto finalCharSize = ::MultiByteToWideChar(codepage, MB_ERR_INVALID_CHARS, str.c_str(), ansiByteSize,
                                                         &returnValue[0], wideCharSize);
        assert(finalCharSize == wideCharSize);
        return returnValue;
#else
        return details::converterX.from_bytes(str);
#endif
    }

    template<class wstring = std::wstring, class Traits = std::string::traits_type, class Alloc = std::string::allocator_type>
    inline wstring
    s2ws(const std::basic_string<char, Traits, Alloc> &str, const UINT codepage = details::default_codepage)
    {
#ifdef _WIN32
        const std::string::size_type limit = (std::numeric_limits<int>::max)();
        assert(str.size() < limit);
        const int ansiByteSize = static_cast<int>(str.size());
        const auto wideCharSize = ::MultiByteToWideChar(codepage, MB_ERR_INVALID_CHARS, str.c_str(), ansiByteSize,
                                                        nullptr, 0);

        wstring returnValue(wideCharSize, L'\0');
        const auto finalCharSize = ::MultiByteToWideChar(codepage, MB_ERR_INVALID_CHARS, str.c_str(), ansiByteSize,
                                                         &returnValue[0], wideCharSize);
        assert(finalCharSize == wideCharSize);
        return returnValue;
#else
        return details::converterX.from_bytes(str);
#endif
    }

    template<class wstring = std::wstring>
    inline wstring s2ws(const char *str, const UINT codepage = details::default_codepage)
    {
#ifdef _WIN32
        const std::string::size_type limit = (std::numeric_limits<int>::max)();
        const auto wideCharSize = ::MultiByteToWideChar(codepage, MB_ERR_INVALID_CHARS, str, -1,
                                                        nullptr, 0);

        wstring returnValue(wideCharSize, L'\0');
        const auto finalCharSize = ::MultiByteToWideChar(codepage, MB_ERR_INVALID_CHARS, str, -1, returnValue.data(),
                                                         wideCharSize);
        assert(finalCharSize == wideCharSize);
        return returnValue;
#else
        return details::converterX.from_bytes(str);
#endif
    }

    template<class wstring = std::wstring>
    inline wstring s2ws(const char *str, size_t strlen, const UINT codepage = details::default_codepage)
    {
#ifdef _WIN32
        constexpr std::string::size_type limit = (std::numeric_limits<int>::max)();
        assert(strlen < limit);
        const auto wideCharSize = ::MultiByteToWideChar(codepage, MB_ERR_INVALID_CHARS, str, static_cast<int>(strlen),
                                                        nullptr, 0);

        wstring returnValue(wideCharSize, L'\0');
        const auto finalCharSize = ::MultiByteToWideChar(codepage, MB_ERR_INVALID_CHARS, str, static_cast<int>(strlen),
                                                         returnValue.data(), wideCharSize);
        assert(finalCharSize == wideCharSize);
        return returnValue;
#else
        return details::converterX.from_bytes(str);
#endif
    }

    template<class string = std::string>
    inline string ws2s(const std::wstring &wstr, const UINT codepage = details::default_codepage)
    {
#ifdef _WIN32
        if (wstr.empty()) return string();
        const auto size_needed = ::WideCharToMultiByte(codepage, 0, wstr.c_str(), static_cast<int>(wstr.size()), NULL,
                                                       0, NULL, NULL);
        string strTo(static_cast<size_t>(size_needed), 'I');
        ::WideCharToMultiByte(codepage, 0, wstr.c_str(), static_cast<int>(wstr.size()), strTo.data(), size_needed, NULL,
                              NULL);
        return strTo;
#else
        return details::converterX.to_bytes(wstr);
#endif
    }

    template<class string = std::string, class Traits = std::wstring::traits_type, class Alloc = std::wstring::allocator_type>
    inline string
    ws2s(const std::basic_string<wchar_t, Traits, Alloc> &wstr, const UINT codepage = details::default_codepage)
    {
#ifdef _WIN32
        if (wstr.empty()) return string();
        int size_needed = ::WideCharToMultiByte(codepage, 0, wstr.c_str(), static_cast<int>(wstr.size()), NULL, 0, NULL,
                                                NULL);
        string strTo(size_needed, 'I');
        ::WideCharToMultiByte(codepage, 0, wstr.c_str(), static_cast<int>(wstr.size()), strTo.data(), size_needed, NULL,
                              NULL);
        return strTo;
#else
        return details::converterX.to_bytes(wstr);
#endif
    }

    template<class string = std::string>
    inline string ws2s(const wchar_t *wstr, const UINT codepage = details::default_codepage)
    {
#ifdef _WIN32
        if (wstr == nullptr || *wstr == wchar_t(0)) return string();
        const auto size_needed = ::WideCharToMultiByte(codepage, 0, wstr, -1, NULL, 0, NULL, NULL);
        string ret(static_cast<size_t>(size_needed), '\0');
        ::WideCharToMultiByte(codepage, 0, wstr, -1, ret.data(), size_needed, NULL, NULL);
        return ret;
#else
        return details::converterX.to_bytes(wstr);
#endif
    }

    template<class string = std::string>
    inline string ws2s(const wchar_t *wstr, size_t wstrlen, const UINT codepage = details::default_codepage)
    {
#ifdef _WIN32
        if (wstr == nullptr || *wstr == wchar_t(0)) return string();
        const auto size_needed = ::WideCharToMultiByte(codepage, 0, wstr, static_cast<int>(wstrlen), NULL, 0, NULL,
                                                       NULL);
        string ret(static_cast<size_t>(size_needed), '\0');
        ::WideCharToMultiByte(codepage, 0, wstr, static_cast<int>(wstrlen), ret.data(), size_needed, NULL, NULL);
        return ret;
#else
        return details::converterX.to_bytes(wstr);
#endif
    }

    template<typename string>
    inline bool findStringIC(const string &strHaystack, const string &strNeedle)
    {

        auto it = std::search(
                strHaystack.begin(), strHaystack.end(),
                strNeedle.begin(), strNeedle.end(),
                [](typename string::value_type ch1, typename string::value_type ch2)
                { return std::toupper(ch1, details::loc) == std::toupper(ch2, details::loc); }
        );
        return (it != strHaystack.end());
    }

    template<size_t MaxLength = (std::numeric_limits<size_t>::max)()>
    inline bool wstring_ends_with(const wchar_t *str, const wchar_t *suffix)
    {
        const size_t str_len = str != nullptr ? wcsnlen(str, MaxLength) : 0;
        const size_t suffix_len = suffix ? wcsnlen(suffix, MaxLength) : 0;

        return
                (str_len >= suffix_len) &&
                (0 == wcsncmp(str + (str_len - suffix_len), suffix, MaxLength));
    }

    template<size_t MaxLength = (std::numeric_limits<size_t>::max)()>
    inline bool wstring_starts_with(const wchar_t *str, const wchar_t *suffix)
    {
        const size_t str_len = str != nullptr ? wcsnlen(str, MaxLength) : 0;
        const size_t suffix_len = suffix ? wcsnlen(suffix, MaxLength) : 0;
        const std::wstring_view str_view(str, str_len);
        const std::wstring_view suffix_view(suffix, suffix_len);

        return
                (str_len >= suffix_len) &&
                str_view.find(suffix_view) == 0;
    }

    template<size_t MaxLength = (std::numeric_limits<size_t>::max)()>
    inline bool wstring_starts_with(const std::wstring &str, const wchar_t *suffix)
    {
        const size_t str_len = str.size();
        const size_t suffix_len = suffix ? wcsnlen(suffix, MaxLength) : 0;
        const std::wstring_view str_view(str);
        const std::wstring_view suffix_view(suffix, suffix_len);

        return
                (str_len >= suffix_len) &&
                str_view.find(suffix_view) == 0;
    }

    template<size_t MaxLength = (std::numeric_limits<size_t>::max)()>
    inline bool wstring_starts_with(const std::wstring_view &str, const wchar_t *suffix)
    {
        const size_t str_len = str.size();
        const size_t suffix_len = suffix ? wcsnlen(suffix, MaxLength) : 0;
        const std::wstring_view str_view(str);
        const std::wstring_view suffix_view(suffix, suffix_len);

        return
                (str_len >= suffix_len) &&
                str_view.find(suffix_view) == 0;
    }

    template<typename T>
    std::basic_string_view<T> trim(const std::basic_string_view<T> &s)
    {
        std::basic_string_view<T> ret = s;
        bool stable = false;
        while (!stable)
        {
            stable = true;
            for (const T c : {T(' '), T('\t'), T('\n'), T('\r')})
            {
                size_t prev = ret.size();
                ret = trim<T>(ret, c);
                stable &= (ret.size() == prev);
            }
        }

        return ret;
    }

    template<typename T>
    std::basic_string_view<T> trim(const std::basic_string_view<T> &s, T c)
    {
        std::basic_string_view<T> ret = s;
        while (!ret.empty() && ret.front() == c)
        {
            ret.remove_prefix(1);
        }

        while (!ret.empty() && ret.back() == c)
        {
            ret.remove_suffix(1);
        }

        return ret;
    }
}
