#pragma once

#include <optional>
#include <vector>
#include <TlHelp32.h>
#include <memory>
#include <cassert>
#include "../../../windows_include.hpp"
#include "../../../sandbox/config/Config.hpp"
#include "DefaultSafeHandle.hpp"

namespace maxisoft::utils::sys::safer
{
    struct SAFER_LPPROC_THREAD_ATTRIBUTE_LIST
    {
        using Config = maxisoft::sandbox::config::Config;
    public:
        operator LPPROC_THREAD_ATTRIBUTE_LIST()
        { return reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(buffer); }

        std::byte *buffer = nullptr;
        ProcessHandle explorer_process;
        DWORD thread_attribute_child_process_policy_flag;
        DWORD64 proc_thread_attribute_mitigation_policy_flag;

        explicit SAFER_LPPROC_THREAD_ATTRIBUTE_LIST() = default;

        ~SAFER_LPPROC_THREAD_ATTRIBUTE_LIST()
        {
            if (buffer != nullptr)
            {
                DeleteProcThreadAttributeList(static_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(*this));
            }
        }

        std::byte *alloc(const size_t size)
        {
            if (buffer != nullptr)
            {
                throw std::exception("already initialized buffer");
            }
            const auto tmp = static_cast<std::byte *>(HeapAlloc(GetProcessHeap(), 0, size));
            if (tmp == nullptr)
            {
                throw std::exception("HeapAlloc");
            }
            buffer = tmp;
            return tmp;
        }

        static std::unique_ptr<SAFER_LPPROC_THREAD_ATTRIBUTE_LIST>
        create(const Config &config, const ProcessHandle &explorer_process)
        {
            const DWORD startupinfo_attribute_count = (config.disable_subprocess_spawn ? 1 : 0)
                                                      + (config.fake_parent_process && explorer_process ? 1 : 0)
                                                      + (!config.proc_thread_attribute_mitigation_policy().empty() ? 1
                                                                                                                   : 0);
            if (startupinfo_attribute_count <= 0) return {};
            SIZE_T attribute_list_size = 0;
            if (InitializeProcThreadAttributeList(nullptr, startupinfo_attribute_count, 0, &attribute_list_size) ==
                FALSE &&
                GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            {
                throw std::exception("InitializeProcThreadAttributeList failed to get size");
            }

            auto ret = std::make_unique<SAFER_LPPROC_THREAD_ATTRIBUTE_LIST>();
            auto buf = ret->alloc(attribute_list_size);


            if (InitializeProcThreadAttributeList(static_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(*ret),
                                                  startupinfo_attribute_count,
                                                  0,
                                                  &attribute_list_size) == FALSE)
            {
                throw std::exception("InitializeProcThreadAttributeList");
            }

            if (config.fake_parent_process && explorer_process)
            {
                DefaultSafeHandle cpy{};
                if (!DuplicateHandle(GetCurrentProcess(), explorer_process, GetCurrentProcess(), cpy.unsafe_get_ptr(),
                                     0, false,
                                     DUPLICATE_SAME_ACCESS))
                {
                    throw std::exception("DuplicateHandle");
                }
                ret->explorer_process = std::move(cpy);
                if (UpdateProcThreadAttribute(*ret,
                                              0,
                                              PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                              reinterpret_cast<PVOID>(ret->explorer_process.unsafe_get_ptr()),
                                              sizeof(HANDLE),
                                              nullptr,
                                              nullptr) == FALSE)
                {
                    throw std::exception("UpdateProcThreadAttribute");
                }
            }

            if (config.disable_subprocess_spawn)
            {
                DWORD & flag = std::ref(ret->thread_attribute_child_process_policy_flag);
                flag |= PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
                if (UpdateProcThreadAttribute(*ret,
                                              0,
                                              PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY,
                                              &flag,
                                              sizeof(decltype(flag)),
                                              nullptr,
                                              nullptr) == FALSE)
                {
                    throw std::exception("UpdateProcThreadAttribute");
                }
            }

            if (!config.proc_thread_attribute_mitigation_policy().empty())
            {
                DWORD64 &flag = std::ref(ret->proc_thread_attribute_mitigation_policy_flag);
                for (const auto &value : config.proc_thread_attribute_mitigation_policy())
                {
                    flag |= value;
                }
                if (flag != 0 && UpdateProcThreadAttribute(*ret,
                                                           0,
                                                           PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                                                           &flag,
                                                           sizeof(decltype(flag)),
                                                           nullptr,
                                                           nullptr) == FALSE)
                {
                    throw std::exception("UpdateProcThreadAttribute");
                }
            }

            return ret;
        }
    };
}

