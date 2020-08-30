#include "TokenProcess.hpp"

#include <processthreadsapi.h>
#include <sddl.h>

namespace maxisoft::sandbox
{
    namespace detail
    {
        template<bool Throw>
        PSID create_well_known_sid(WELL_KNOWN_SID_TYPE type, PSID domain)
        {
            DWORD SidSize = SECURITY_MAX_SID_SIZE;
            PSID ret = LocalAlloc(LMEM_FIXED, SidSize);
            if (!::CreateWellKnownSid(type, domain, ret, &SidSize))
            {
                if (ret != nullptr)
                {
                    LocalFree(ret);
                }
                ret = nullptr;
                if constexpr (Throw)
                {
                    throw std::exception("unable to get well known sid");
                }
            }
            return ret;
        }

        template<class Token>
        BOOL remove_privileges(const Config &config, const Token &token)
        {
            const auto privilege_to_remove = config.se_privileges();
            const size_t vector_size = (sizeof(TOKEN_PRIVILEGES) + (sizeof(LUID_AND_ATTRIBUTES) * privilege_to_remove.size())) / sizeof(TOKEN_PRIVILEGES) + 1;
            std::vector<TOKEN_PRIVILEGES> newState{ vector_size };
            const auto pNewState = newState.data();

            pNewState->PrivilegeCount = static_cast<DWORD>(privilege_to_remove.size());

            for (size_t i = 0; i < privilege_to_remove.size(); ++i)
            {
                auto& to_remove = privilege_to_remove.at(i);
                assert(!to_remove.empty());
                if (!LookupPrivilegeValue(nullptr, maxisoft::utils::s2ws(to_remove).c_str(), &pNewState->Privileges[i].Luid))
                {
                    throw std::exception("unable to get LookupPrivilegeValue");
                }
                pNewState->Privileges[i].Attributes = SE_PRIVILEGE_REMOVED;
            }

            return ::AdjustTokenPrivileges(token, FALSE, pNewState, 0, 0, 0);
        }
    }

    std::unique_ptr<TokenHandle> get_default_token(DWORD desired_token_access)
    {
        auto ret = std::make_unique<TokenHandle>();
        if (::OpenThreadToken(::GetCurrentThread(), desired_token_access, true, ret->unsafe_get_ptr()) == 0)
        {
            if (::OpenProcessToken(::GetCurrentProcess(), desired_token_access, ret->unsafe_get_ptr()) == 0)
            {
                throw std::exception("OpenProcessToken");
            }
        }
        return ret;
    }

    std::unique_ptr<TokenHandle> create_token(const Config &config)
    {
        constexpr DWORD desired_token_access = TOKEN_DUPLICATE |
                                               TOKEN_ADJUST_DEFAULT |
                                               TOKEN_QUERY |
                                               TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_PRIVILEGES | TOKEN_READ;

        auto def_token = get_default_token(desired_token_access);
        TokenHandle access_token(std::move(*def_token.get()));


        struct sidvector : public std::vector<SID_AND_ATTRIBUTES>
        {

            explicit sidvector(size_t len) : std::vector<SID_AND_ATTRIBUTES>(len)
            {
            }
            ~sidvector()
            {
                for (const auto& element : *this)
                {
                    if (element.Sid)
                    {
                        ::LocalFree(element.Sid);
                    }
                }
            }
        } adminSID(5);


        SID_IDENTIFIER_AUTHORITY SIDAuth = SECURITY_NT_AUTHORITY;
        if (!AllocateAndInitializeSid(&SIDAuth, 2,
                                      SECURITY_BUILTIN_DOMAIN_RID,
                                      DOMAIN_ALIAS_RID_ADMINS,
                                      0, 0, 0, 0, 0, 0,
                                      &adminSID.front().Sid))
        {
            throw std::exception("AllocateAndInitializeSid");
        }


        ConvertStringSidToSid(TEXT("S-1-5-114"), &adminSID.at(1).Sid);
        ConvertStringSidToSid(TEXT("S-1-5-32-544"), &adminSID.at(2).Sid);
        adminSID.at(3).Sid = detail::create_well_known_sid(WinBuiltinAdministratorsSid);
        adminSID.at(4).Sid = detail::create_well_known_sid(WinAccountAdministratorSid);

        for (auto it = adminSID.begin(); it != adminSID.end();)
        {
            if (it->Sid == nullptr || !::IsValidSid(it->Sid))
            {
                if (it->Sid)
                {
                    ::LocalFree(it->Sid);
                }
                it = adminSID.erase(it);
            }
            else
            {
                it->Attributes = SE_GROUP_USE_FOR_DENY_ONLY;
                ++it;
            }

        }

        TokenHandle tmp_new_token;
        if (config.disable_admin)
        {
            if (!::CreateRestrictedToken(access_token, 0, static_cast<DWORD>(adminSID.size()), adminSID.data(), 0, 0, 0, 0,
                                         tmp_new_token.unsafe_get_ptr()))
            {
                size_t count = 0;
                for (auto& sid : adminSID)
                {
                    if (sid.Sid == nullptr || !::IsValidSid(sid.Sid)) continue;
                    const TokenHandle& loop_tmp = tmp_new_token ? tmp_new_token : access_token;
                    if (::CreateRestrictedToken(loop_tmp, 0, 1, std::addressof(sid), 0, 0, 0, 0,
                                                tmp_new_token.unsafe_get_ptr()))
                    {
                        ++count;
                    }
                }
                if (count == 0)
                {
                    throw std::exception("CreateRestrictedToken");
                }
            }
        }
        else
        {
            tmp_new_token = std::move(access_token);
            if (::OpenThreadToken(GetCurrentThread(), desired_token_access, true, access_token.unsafe_get_ptr()) == 0)
            {
                if (::OpenProcessToken(::GetCurrentProcess(), desired_token_access, access_token.unsafe_get_ptr()) == 0)
                {
                    throw std::exception("OpenProcessToken");
                }
            }
        }

        auto new_token = std::make_unique<TokenHandle>();
        if (!::DuplicateTokenEx(tmp_new_token,
                                0,
                                nullptr,
                                SecurityImpersonation,
                                TokenImpersonation,
                                new_token->unsafe_get_ptr()))
        {
            throw std::exception("DuplicateTokenEx");
        }


        TOKEN_MANDATORY_LABEL inegrity_level = { 0 };
        DWORD returnlength = 0;
        auto res = ::GetTokenInformation(access_token, TokenIntegrityLevel, &inegrity_level, sizeof(decltype(inegrity_level)), &returnlength);
        auto integrity_level = config.integrity_level();
        if (!integrity_level.empty())
        {
            TOKEN_MANDATORY_LABEL low = { 0 };
            if (!::ConvertStringSidToSid(maxisoft::utils::s2ws(integrity_level).c_str(), &low.Label.Sid) || !IsValidSid(low.Label.Sid))
            {
                throw std::exception("ConvertStringSidToSid");
            }
            low.Label.Attributes = SE_GROUP_INTEGRITY;
            res = ::SetTokenInformation(*new_token, TokenIntegrityLevel, &low, sizeof(decltype(low)) + GetLengthSid(low.Label.Sid));
            if (!res)
            {
                throw std::exception("SetTokenInformation");
            }
        }


        if (!detail::remove_privileges(config, *new_token))
        {
            throw std::exception("unable to Remove Privileges");
        }

        return new_token;
    }
}