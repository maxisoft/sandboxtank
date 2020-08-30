#include "SharedMemData.hpp"

namespace maxisoft::sandbox
{

    ProcessContext &SharedMemData::get_current_context()
    {
        if (auto ctx = get_context(GetCurrentProcessId()))
        {
            return *ctx;
        }
        throw std::exception("unable to get current context");
    }

    std::optional<std::reference_wrapper<ProcessContext>> SharedMemData::get_context(const DWORD pid)
    {
        for (auto &context : contexts)
        {
            if (context.pid == pid)
            {
                return std::ref(context);
            }
        }
        return {};
    }

    bool SharedMemData::valid() const
    {
        return magic == s_magic_array && build_date_hash == s_build_date_hash && config_length <= config.size();
    }
}