#pragma once

#include <string>
#include <array>
#include "../windows_include.hpp"
#include <Objbase.h>
#include <Rpc.h>

#pragma comment(lib, "Rpcrt4.lib")

namespace maxisoft::utils
{
    static UUID GenerateUUID()
    {

        UUID ret;
        auto res = UuidCreate(&ret);
        if ((res != S_OK) & (res != RPC_S_UUID_LOCAL_ONLY))
        {
            res = UuidCreateSequential(&ret);
            if ((res != S_OK) & (res != RPC_S_UUID_LOCAL_ONLY))
            {
                res = CoCreateGuid(&ret);
                if (res != S_OK)
                {
                    throw std::exception("unable to create uuid");
                }
            }
        }
        return ret;
    }


    static std::wstring UUIDToString(const UUID guid)
    {
        std::array<wchar_t, 128> buff;
        const auto r = StringFromGUID2(guid, buff.data(), static_cast<int>(buff.size()));
        if (r > 0)
        {
            return std::wstring(buff.data(), r - 1);
        }
        return {};
    }
}

