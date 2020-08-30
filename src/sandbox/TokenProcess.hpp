#pragma once
#include <memory>
#include "../windows_include.hpp"
#include "../utils/sys/safer/__all__.hpp"
#include "config/Config.hpp"

namespace maxisoft::sandbox
{
    using maxisoft::utils::sys::safer::TokenHandle;
    using maxisoft::sandbox::config::Config;

	namespace detail
	{
		template <bool Throw = true>
		static PSID create_well_known_sid(WELL_KNOWN_SID_TYPE type, PSID domain = nullptr);

        template <class Token = TokenHandle>
		static BOOL remove_privileges(const Config& config, const Token & token);

    }

	std::unique_ptr<TokenHandle> get_default_token(DWORD desired_token_access);

	std::unique_ptr<TokenHandle> create_token(const Config& config);
}
