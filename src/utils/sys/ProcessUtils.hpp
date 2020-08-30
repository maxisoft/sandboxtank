#pragma once
#include "../../windows_include.hpp"
#include <optional>
#include "safer/__all__.hpp"

namespace maxisoft::utils::sys
{
    using maxisoft::utils::sys::safer::ProcessHandle;

    ProcessHandle current_process();


    std::optional<DWORD> parent_process_id();
}