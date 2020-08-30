#pragma once

#include <cassert>
#include <filesystem>
#include <array>
#include <optional>
#include <map>
#include <vector>
#include <tchar.h>
#include <cstdio>


namespace maxisoft::sandbox
{
    struct ProgramArgs
    {
        size_t argc;
        std::filesystem::path program;
        std::filesystem::path config;
        std::optional<std::wstring> sessionid;
        std::vector<std::wstring> additional_args;
        std::optional<std::wstring> user;
        std::optional<std::wstring> password;
        std::optional<std::wstring> domain;
        std::filesystem::path working_directory;

        [[nodiscard]] std::wstring to_child_args(bool prepend_current_process) const;

        static ProgramArgs parse_args(int argc, wchar_t *argv[]);
    };


}
