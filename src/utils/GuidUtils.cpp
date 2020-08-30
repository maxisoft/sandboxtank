#include "GuidUtils.hpp"
#include <Objbase.h>

#pragma comment(lib, "Rpcrt4.lib")

namespace maxisoft::utils
{
    UUID GenerateUUID()
    {

        UUID ret;
        auto res = UuidCreate(&ret);
        if (res != S_OK)
        {
            res = UuidCreateSequential(&ret);
            if (res != S_OK)
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

    std::wstring UUIDToString(const UUID guid)
    {
        std::array<wchar_t, 128> buff{};
        const auto r = StringFromGUID2(guid, buff.data(), static_cast<int>(buff.size()));
        if (r > 0)
        {
            return std::wstring(buff.data(), r - 1);
        }
        return {};
    }
}