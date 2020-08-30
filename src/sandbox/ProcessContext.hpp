#pragma once

#include "../windows_include.hpp"
#include "../utils/__all__.hpp"
#include <array>
#include <optional>

namespace maxisoft::sandbox
{
    struct ProcessContext
    {
        using Handle = HANDLE;
        using ProcessHandle = maxisoft::utils::sys::safer::ProcessHandle;

        DWORD pid = 0;
        Handle target_process_handle = ProcessHandle();
        Handle explorer_handle = ProcessHandle();
        Handle injected_parent_process = ProcessHandle();
        std::array<wchar_t, 255> user_sid = {};

        explicit ProcessContext() = default;
        ProcessContext(const ProcessContext&) = delete;

        ProcessContext(ProcessContext&& other) noexcept;

        void cleanup();

        ~ProcessContext()
        {
            cleanup();
        }

        ProcessContext& operator=(ProcessContext&& other) noexcept;
    };
}
