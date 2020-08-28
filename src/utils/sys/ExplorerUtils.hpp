#pragma once
#include "safer/__all__.hpp"
#include <memory>
#include <processthreadsapi.h>
#include "../StringUtils.h"
#include <optional>
#include <TlHelp32.h>
#include <map>

namespace maxisoft::utils::sys
{
    using SnapshotHandle = ::maxisoft::utils::sys::safer::DefaultSafeHandle;
    using ::maxisoft::utils::sys::safer::ProcessHandle;
    constexpr auto EXPLORER_PROCESS_NAME = TEXT("explorer.exe");

	inline ProcessHandle GetExplorerProcess(const DWORD process_access = PROCESS_CREATE_PROCESS | PROCESS_QUERY_LIMITED_INFORMATION)
	{
		const auto pid = ::GetCurrentProcessId();
		const SnapshotHandle h(::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
		if (!h)
		{
			throw std::exception("unable to query CreateToolhelp32Snapshot");
		}

		PROCESSENTRY32 pe = { 0 };
		pe.dwSize = sizeof(PROCESSENTRY32);

		//index process by pid
		std::map<decltype(pe.th32ProcessID), decltype(pe)> processes{};

		if (::Process32First(h, &pe))
		{
			do
			{
				processes.try_emplace(pe.th32ProcessID, pe);
			} while (::Process32Next(h, &pe));
		}

		//find direct explorer parent process
		std::optional<decltype(pe.th32ProcessID)> explorer_pid{};
		for (auto it = processes.find(pid); it != processes.end();)
		{
			if (maxisoft::utils::wstring_ends_with<MAX_PATH>(it->second.szExeFile, EXPLORER_PROCESS_NAME))
			{
				explorer_pid = it->first;
				break;
			}
			it = processes.find(it->second.th32ParentProcessID);
		}

		if (explorer_pid)
		{
			auto process = ::OpenProcess(process_access, false, *explorer_pid);
			if (process)
			{
				return static_cast<ProcessHandle>(process);
			}
		}

		// try to find any exporer process
		for (const auto & processe : processes)
		{
			if (maxisoft::utils::wstring_ends_with<MAX_PATH>(processe.second.szExeFile, EXPLORER_PROCESS_NAME))
			{
                auto process = ::OpenProcess(process_access, false, processe.first);
				if (process)
				{
                    return static_cast<ProcessHandle>(process);
				}
			}
		}

		return {};
	}
}
