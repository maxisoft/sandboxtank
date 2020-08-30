#include "ProcessContext.hpp"

namespace maxisoft::sandbox
{

    ProcessContext::ProcessContext(ProcessContext &&other) noexcept: pid(other.pid),
                                                                     target_process_handle(other.target_process_handle),
                                                                     explorer_handle(other.explorer_handle),
                                                                     injected_parent_process(other.injected_parent_process),
                                                                     user_sid(other.user_sid)
    {
        other.cleanup();
    }

    void ProcessContext::cleanup()
    {
        if (pid == GetCurrentProcessId())
        {
            for (Handle& h : {std::ref(target_process_handle),
                              std::ref(explorer_handle),
                              std::ref(injected_parent_process)}) {
                if (h != maxisoft::utils::sys::safer::ProcessHandle::NullValue)
                {
                    maxisoft::utils::sys::safer::ProcessHandle::Destructor(h);
                    h = maxisoft::utils::sys::safer::ProcessHandle::NullValue;
                }
            }
        }
        else
        {
            for (Handle & h : {std::ref(target_process_handle),
                               std::ref(explorer_handle),
                               std::ref(injected_parent_process)}) {
                h = maxisoft::utils::sys::safer::ProcessHandle::NullValue;
            }
        }
    }

    ProcessContext &ProcessContext::operator=(ProcessContext &&other) noexcept
    {
        cleanup();
        pid = other.pid;
        target_process_handle = other.target_process_handle;
        explorer_handle = other.explorer_handle;
        injected_parent_process = other.injected_parent_process;
        other.cleanup();
        return *this;
    }
}