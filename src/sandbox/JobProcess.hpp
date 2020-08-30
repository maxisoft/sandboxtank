#pragma once

#include <memory>
#include "../windows_include.hpp"

#include "../utils/sys/safer/__all__.hpp"
#include "../utils/StringUtils.hpp"
#include "config/Config.hpp"

namespace maxisoft::sandbox
{
    using JobHandle = ::maxisoft::utils::sys::safer::JobHandle;
    using namespace maxisoft::sandbox::config;
    using TokenHandle = ::maxisoft::utils::sys::safer::TokenHandle;
    extern JobHandle create_job(const Config &config, const TokenHandle &jobtoken);
}


