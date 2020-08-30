#pragma once

#include <optional>
#include <memory>
#include "../../../sandbox/config/Config.hpp"
#include "DefaultSafeHandle.hpp"

namespace maxisoft::utils::sys::safer
{
    struct SAFER_LPPROC_THREAD_ATTRIBUTE_LIST
    {
        using Config = maxisoft::sandbox::config::Config;
    public:
        std::byte *buffer = nullptr;

        ProcessHandle explorer_process;
        DWORD thread_attribute_child_process_policy_flag;
        DWORD64 proc_thread_attribute_mitigation_policy_flag;
        explicit SAFER_LPPROC_THREAD_ATTRIBUTE_LIST() = default;

        ~SAFER_LPPROC_THREAD_ATTRIBUTE_LIST();

        operator LPPROC_THREAD_ATTRIBUTE_LIST();

        std::byte *alloc(size_t size);

        static std::unique_ptr<SAFER_LPPROC_THREAD_ATTRIBUTE_LIST>
        create(const Config &config, const ::HANDLE &explorer_process);

        static std::unique_ptr<SAFER_LPPROC_THREAD_ATTRIBUTE_LIST>
        create(const Config &config, const ProcessHandle &explorer_process);
    };
}

