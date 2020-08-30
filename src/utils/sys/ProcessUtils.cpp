#include "ProcessUtils.hpp"
#include "../../windows_include.hpp"
#include <TlHelp32.h>
#include <vector>

namespace maxisoft::utils::sys
{

    ProcessHandle current_process()
    {
        auto h = OpenProcess(PROCESS_ALL_ACCESS, false, GetCurrentProcessId());
        if (h == nullptr) {
            throw std::exception("OpenProcess");
        }
        return static_cast<ProcessHandle>(h);
    }

    std::optional<DWORD> parent_process_id()
    {
        const auto pid = GetCurrentProcessId();
        const ProcessHandle h(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
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