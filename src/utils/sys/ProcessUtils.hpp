#pragma once
#include "../../windows_include.hpp"
#include <optional>
#include <vector>
#include <TlHelp32.h>
#include <memory>
#include <cassert>
#include "safer/__all__.hpp"
#include "../../sandbox/config/Config.hpp"

namespace maxisoft::utils::sys
{
    using maxisoft::utils::sys::safer::DefaultSafeHandle;
    using maxisoft::utils::sys::safer::ProcessHandle;
    using Config = maxisoft::sandbox::config::Config;


    static ProcessHandle current_process()
    {
        auto h = OpenProcess(PROCESS_ALL_ACCESS, false, GetCurrentProcessId());
        if (h == nullptr) {
            throw std::exception("OpenProcess");
        }
        return DefaultSafeHandle(h);
    }


    static std::optional<DWORD> parent_process_id()
    {
        const auto pid = GetCurrentProcessId();
        const DefaultSafeHandle h(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!h)
        {
            throw std::exception("unable to query CreateToolhelp32Snapshot");
        }

        PROCESSENTRY32 pe = {0};
        pe.dwSize = sizeof(PROCESSENTRY32);

        if (::Process32First(h, &pe))
        {
            do
            {
                if (pe.th32ProcessID == pid)
                {
                    return pe.th32ParentProcessID;
                }
            } while (::Process32Next(h, &pe));
        }

        return {};
    }
}