#pragma once

#include "../../../sandbox/ProgramArgs.hpp"
#include "../../../sandbox/Globals.hpp"
#include "../../../../cpp-mmf/memory_mapped_file.hpp"
#include "../../../sandbox/SharedMemory.hpp"
#include "../../../DesktopACL.h"
#include "../../../sandbox/TokenProcess.hpp"
#include "../../../sandbox/JobProcess.hpp"
#include "../../StringUtils.h"
#include "../../../sandbox/config/Config.hpp"
#include <cassert>
#include <thread>
#include "../../__all__.hpp"
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
#include "PROCESS_INFORMATION.hpp"

namespace maxisoft::utils::sys::safer
{
    class SAFE_PROCESS_INFORMATION
    {
        using ProcessHandle = maxisoft::utils::sys::safer::ProcessHandle;
        using ThreadHandle = maxisoft::utils::sys::safer::ThreadHandle;
    public:
        ProcessHandle hProcess = {};
        ThreadHandle hThread = {};
        DWORD dwProcessId = 0;
        DWORD dwThreadId = 0;

        explicit SAFE_PROCESS_INFORMATION() = default;

        SAFE_PROCESS_INFORMATION(PROCESS_INFORMATION &&pi) : hProcess(pi.hProcess), hThread(pi.hThread),
                                                             dwProcessId(pi.dwProcessId), dwThreadId(pi.dwThreadId)
        {
            memset(std::addressof(pi), 0, sizeof(decltype(pi)));
        }

        [[noreturn]] SAFE_PROCESS_INFORMATION &operator=(PROCESS_INFORMATION &&pi)
        {
            hProcess = pi.hProcess;
            hThread = pi.hThread;
            dwProcessId = pi.dwProcessId;
            dwThreadId = pi.dwThreadId;
            memset(std::addressof(pi), 0, sizeof(decltype(pi)));
            return *this;
        }
    };
}
