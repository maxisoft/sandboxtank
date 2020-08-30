#pragma once

#include <string>
#include <array>
#include "../windows_include.hpp"
#include <Rpc.h>

namespace maxisoft::utils
{
    UUID GenerateUUID();
    std::wstring UUIDToString(UUID guid);
}

