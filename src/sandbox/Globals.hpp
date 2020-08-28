#pragma once

#include "../../cpp-mmf/memory_mapped_file.hpp"
#include "SharedMemory.hpp"
#include "../DesktopACL.h"
#include "TokenProcess.hpp"
#include "JobProcess.hpp"
#include "../utils/StringUtils.h"
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
#include <Windows.h>
#include <vector>
#include <tchar.h>
#include <cstdio>
#include "Globals.hpp"

namespace maxisoft::sandbox
{
    class Globals final
    {
        using ProcessHandle = maxisoft::utils::sys::safer::ProcessHandle;
        using Config = maxisoft::sandbox::config::Config;
    public:
        explicit Globals() : m_cwd(MAX_PATH, wchar_t(0)),
                             m_process(OpenProcess(PROCESS_ALL_ACCESS, false, GetCurrentProcessId())), m_config()
        {
            const auto len = GetCurrentDirectory(static_cast<DWORD>(m_cwd.size()), m_cwd.data());
            if (len <= 0)
            {
                throw std::exception("unable to get CurrentDirectory");
            }
            m_cwd.resize(static_cast<size_t>(len));
        }

    public:
        const std::wstring& working_directory() const
        {
            return m_cwd;
        }

        const ProcessHandle& process() const
        {
            return m_process;
        }

        template <class Handle>
        static bool is_process_in_job(const Handle& handle)
        {
            BOOL ret = false;
            if (!IsProcessInJob(handle, nullptr, &ret))
            {
                throw std::exception("unable to get IsProcessInJob");
            }
            return ret;
        }

        bool is_process_in_job() const
        {
            return is_process_in_job(process());
        }

        const Config& config() const
        {
            return m_config;
        }

        void set_config(Config&& config)
        {
            m_config = config;
        }

        void set_config(const Config& config)
        {
            m_config = config;
        }

    private:
        std::wstring m_cwd;
        ProcessHandle m_process;
        Config m_config;
    };

    extern Globals globals;
}
