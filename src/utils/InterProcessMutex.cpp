#include "../windows_include.hpp"
#include "InterProcessMutex.hpp"
#include <synchapi.h>
#include "StringUtils.hpp"


namespace maxisoft
{

    HANDLE InterProcessMutex::GetOrCreateMutex(const std::wstring &name)
    {
        auto m = ::CreateMutexW(NULL, FALSE, name.c_str());
        auto tries = GetOrCreateMutexMaxTries;
        while (m == nullptr && tries-- > 0)
        {
            auto err = ::GetLastError();
            if (err == ERROR_ACCESS_DENIED || err == ERROR_ALREADY_EXISTS)
            {
                m = ::OpenMutexW(SYNCHRONIZE, false, name.c_str());
                if (m != nullptr) break;
                err = ::GetLastError();
                if (err == ERROR_FILE_NOT_FOUND)
                {
                    m = ::CreateMutexW(NULL, FALSE, name.c_str());
                    continue;
                }
            }
            throw std::exception((std::string("OpenMutexW FAILED with error code: ") + std::to_string(err) +
                                  maxisoft::utils::ws2s(GetErrorAsString(err))).c_str());
        }
        if (m == nullptr)
        {
            throw std::exception(
                    (std::string("CreateMutexW FAILED with error code: ") + std::to_string(::GetLastError()) +
                     maxisoft::utils::ws2s(GetErrorAsString())).c_str());
        }
        return m;
    }

    std::wstring InterProcessMutex::GetErrorAsString(const DWORD errorMessageID)
    {
        if (errorMessageID == 0)
            return std::wstring(); //No error message has been recorded

        LPWSTR messageBuffer = nullptr;
        size_t size = FormatMessageW(
                FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                reinterpret_cast<LPWSTR>(&messageBuffer), 0, NULL);
        std::wstring ret(messageBuffer, size);
        LocalFree(messageBuffer);
        return ret;
    }

    InterProcessMutex::InterProcessMutex(const std::wstring &name) : m_(GetOrCreateMutex(name))
    {
        if (!m_)
        {
            throw std::exception(
                    (std::string("CreateMutexW FAILED with error code: ") + std::to_string(GetLastError()) +
                     maxisoft::utils::ws2s(GetErrorAsString())).c_str());
        }
    }

    InterProcessMutex::InterProcessMutex(InterProcessMutex &&other) noexcept: m_(std::move(other.m_))
    {
    }

    bool InterProcessMutex::valid() const
    {
        return m_.valid();
    }

    bool InterProcessMutex::try_lock()
    {
        const auto res = ::WaitForSingleObject(m_, 0);
        if (res == WAIT_FAILED)
        {
            throw std::exception(
                    (std::string("WaitForSingleObject WAIT_FAILED with error code: ") + std::to_string(GetLastError()) +
                     maxisoft::utils::ws2s(GetErrorAsString())).c_str());
        }
        return res == WAIT_OBJECT_0 || res == WAIT_ABANDONED;
    }

    void InterProcessMutex::lock()
    {
        if (::WaitForSingleObject(m_, INFINITE) == WAIT_FAILED)
        {
            throw std::exception(
                    (std::string("WaitForSingleObject WAIT_FAILED with error code: ") + std::to_string(GetLastError()) +
                     maxisoft::utils::ws2s(GetErrorAsString())).c_str());
        }
    }

    void InterProcessMutex::unlock()
    {
        if (::ReleaseMutex(m_) == 0)
        {
            throw std::exception(
                    (std::string("ReleaseMutex FAILED with error code: ") + std::to_string(GetLastError()) +
                     maxisoft::utils::ws2s(GetErrorAsString())).c_str());
        }
    }
}