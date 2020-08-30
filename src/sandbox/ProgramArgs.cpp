#include "ProgramArgs.hpp"

#include "Globals.hpp"
#include "../../cpp-mmf/memory_mapped_file.hpp"
#include "SharedMemory.hpp"
#include "../DesktopACL.h"
#include "TokenProcess.hpp"
#include "JobProcess.hpp"
#include "config/Config.hpp"
#include <cassert>
#include <thread>
#include "../utils/__all__.hpp"
#include <fstream>
#include <mutex>
#include <ShlObj.h>
#include <filesystem>
#include <array>
#include <optional>
#include <map>
#include <TlHelp32.h>
#include <winsafer.h>
#include <functional>
#include <atomic>
#include <sddl.h>
#include <Psapi.h>
#include <iostream>
#include <UserEnv.h>
#include "../windows_include.hpp"
#include <vector>
#include <tchar.h>
#include <cstdio>

namespace maxisoft::sandbox
{
    std::wstring ProgramArgs::to_child_args(bool prepend_current_process) const
    {
        using namespace maxisoft::utils;
        std::wstringstream ss{};

        const auto append_arg = [&ss](const std::wstring &s)
        {
            auto v = trim(std::wstring_view(s));
            v = trim(v, L'"');
            if (v.find(L' ') != std::wstring_view::npos && v.find(L'"') == std::wstring_view::npos)
            {
                ss << L'"';
                ss << v;
                ss << L'"';
            } else
            {
                ss << v;
            }
            ss << L' ';
        };

        if (prepend_current_process)
        {
            append_arg(program);

            if (sessionid)
            {
                ss << L"/sid:";
                append_arg(*sessionid);
            }

            if (domain)
            {
                ss << L"/domain:";
                append_arg(*domain);
            }

            if (!working_directory.empty())
            {
                ss << L"/cwd:";
                append_arg(working_directory);
            }
        }
        for (const auto &arg : additional_args)
        {
            append_arg(arg);
        }
        auto ret = ss.str();
        while (ret.back() == L' ' && !ret.empty())
        {
            ret.back() = wchar_t(0);
            ret.resize(ret.size() - 1);
        }
        return ret;
    }

    ProgramArgs ProgramArgs::parse_args(int argc, wchar_t **argv)
    {
        using namespace maxisoft::utils;
        ProgramArgs ret{};
        ret.argc = argc;
        ret.program = std::wstring(argv[0], wcsnlen(argv[0], MAX_PATH));
        ret.program = absolute(ret.program);

        bool accept_additional_args = true;
        for (size_t i = 1; i < argc; ++i)
        {
            ret.additional_args.emplace_back(argv[i]);
            auto &arg = ret.additional_args.back();
            auto arg_view = trim(std::wstring_view(arg));
            arg_view.remove_prefix(arg_view.front() == L'"' ? 1 : 0);
            accept_additional_args &= wstring_starts_with<MAX_PATH>(arg_view, L"--");
            if (accept_additional_args)
            {
                if (wstring_starts_with<MAX_PATH>(arg_view, L"/sid:"))
                {
                    if (!ret.sessionid)
                    {
                        std::wstring_view v(arg_view);
                        v.remove_prefix(wcslen(L"/sid:"));
                        ret.sessionid = trim(v);
                        ret.additional_args.pop_back();
                        continue;
                    }
                }
                if (wstring_starts_with<MAX_PATH>(arg_view, L"/cwd:"))
                {
                    if (!ret.sessionid)
                    {
                        std::wstring_view v(arg_view);
                        v.remove_prefix(wcslen(L"/cwd:"));
                        ret.working_directory = trim(v);
                        ret.additional_args.pop_back();
                        continue;
                    }
                }
                if (wstring_starts_with<MAX_PATH>(arg_view, L"/config:"))
                {
                    if (ret.config.empty())
                    {
                        std::wstring_view v(arg_view);
                        v.remove_prefix(wcslen(L"/config:"));
                        v.remove_prefix(v.front() == L'"' ? 1 : 0);
                        v.remove_suffix(v.back() == L'"' ? 1 : 0);
                        ret.config = trim(v);
                        ret.additional_args.pop_back();
                        continue;
                    }
                }
                if (wstring_starts_with<MAX_PATH>(arg_view, L"/user:"))
                {
                    if (!ret.user)
                    {
                        std::wstring_view v(arg_view);
                        v.remove_prefix(wcslen(L"/user:"));
                        v.remove_prefix(v.front() == L'"' ? 1 : 0);
                        v.remove_suffix(v.back() == L'"' ? 1 : 0);
                        ret.user = trim(v);
                        ret.additional_args.pop_back();
                        continue;
                    }
                }
                if (wstring_starts_with<MAX_PATH>(arg_view, L"/password:"))
                {
                    if (!ret.password)
                    {
                        std::wstring_view v(arg_view);
                        v.remove_prefix(wcslen(L"/password:"));
                        v.remove_prefix(v.front() == L'"' ? 1 : 0);
                        v.remove_suffix(v.back() == L'"' ? 1 : 0);
                        ret.password = trim(v);
                        ret.additional_args.pop_back();
                        continue;
                    }
                }
                if (wstring_starts_with<MAX_PATH>(arg_view, L"/domain:"))
                {
                    if (!ret.domain)
                    {
                        std::wstring_view v(arg_view);
                        v.remove_prefix(wcslen(L"/domain:"));
                        ret.domain = trim(v);
                        ret.additional_args.pop_back();
                    }
                }
            }
        }
        return ret;
    }
}
