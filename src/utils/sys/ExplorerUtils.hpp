#pragma once
#include "../../windows_include.hpp"
#include "safer/__all__.hpp"
#include <memory>
#include <processthreadsapi.h>
#include "../StringUtils.hpp"
#include <optional>
#include <TlHelp32.h>
#include <map>

namespace maxisoft::utils::sys
{
    using SnapshotHandle = ::maxisoft::utils::sys::safer::DefaultSafeHandle;
    using ::maxisoft::utils::sys::safer::ProcessHandle;
    constexpr auto EXPLORER_PROCESS_NAME = TEXT("explorer.exe");

	ProcessHandle GetExplorerProcess(const DWORD process_access = PROCESS_CREATE_PROCESS | PROCESS_QUERY_LIMITED_INFORMATION);
}
