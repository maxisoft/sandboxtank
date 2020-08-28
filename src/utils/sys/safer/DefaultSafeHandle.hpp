#pragma once
#include "HandleSafe.hpp"
#include <algorithm>

namespace maxisoft::utils::sys::safer
{
    using Handle = ::HANDLE;

    static bool _CloseHandleFct(const Handle h) // NOLINT(bugprone-reserved-identifier)
    {
        return ::CloseHandle(h) != FALSE;
    }

    class DefaultSafeHandle : public HandleSafe<_CloseHandleFct>
    {
    public:
        DefaultSafeHandle() = default;

        explicit DefaultSafeHandle(const Handle handle) : HandleSafe<_CloseHandleFct>(handle)
        {
        }

        explicit DefaultSafeHandle(DefaultSafeHandle&& handle) noexcept : HandleSafe<_CloseHandleFct>(std::move(handle))
        {
        }

        DefaultSafeHandle(const DefaultSafeHandle&) = delete;

        DefaultSafeHandle& operator=(Handle&& h) override
        {
            HandleSafe<_CloseHandleFct>::operator=(std::move(h));
            return *this;
        }

        DefaultSafeHandle& operator=(const Handle h)
        {
            Handle cpy = h;
            HandleSafe<_CloseHandleFct>::operator=(std::move(cpy));
            return *this;
        }


        DefaultSafeHandle& operator=(const DefaultSafeHandle&) = delete;

        DefaultSafeHandle& operator=(DefaultSafeHandle&& h) noexcept
        {
            Handle cpy = h.detach();
            HandleSafe<_CloseHandleFct>::operator=(std::move(cpy));
            return *this;
        }

        HANDLE* unsafe_get_ptr() override
        {
            return HandleSafe<_CloseHandleFct>::unsafe_get_ptr();
        }

        bool cleanup() override
        {
            return HandleSafe<_CloseHandleFct>::cleanup();
        }

        Handle detach() override
        {
            return HandleSafe<_CloseHandleFct>::detach();
        }
    };


    using JobHandle = DefaultSafeHandle;
    using TokenHandle = DefaultSafeHandle;
    using ProcessHandle = DefaultSafeHandle;
    using ThreadHandle = DefaultSafeHandle;
}
