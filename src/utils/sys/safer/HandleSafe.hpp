#pragma once
#include <atomic>
#include <exception>
#include <handleapi.h>

namespace maxisoft::utils::sys::safer
{
    using Handle = ::HANDLE;
	typedef bool(*HandleFunction)(HANDLE);

	template<HandleFunction Destructor_, Handle NullValue_ = nullptr>
	class HandleSafe
	{
	public:
		static constexpr Handle NullValue = NullValue_;
		static constexpr HandleFunction Destructor = Destructor_;

		explicit HandleSafe() : HandleSafe(NullValue)
		{
			
		}
		explicit HandleSafe(const Handle handle) : m_handle(handle)
		{
		}

		explicit HandleSafe(Handle&& handle) : m_handle(handle)
		{
			handle = NullValue;
		}

		explicit HandleSafe(HandleSafe&& h) noexcept : m_handle(h.detach())
		{
		}

		explicit HandleSafe(const HandleSafe& h) = delete;

		virtual ~HandleSafe()
		{
		    try
		    {
		        cleanup();
		    }
		    catch(std::exception&)
            {
                m_handle = NullValue;
            }
		}

		inline Handle handle() const
		{
			return m_handle;
		}

        HandleSafe& operator=(HandleSafe&& h) noexcept
		{
			cleanup();
			m_handle = h.detach();
			return *this;
		}

        virtual HandleSafe& operator=(Handle&& h)
		{
			cleanup();
			m_handle = h;
			h = NullValue;
			return *this;
		}

		HandleSafe& operator=(const HandleSafe& h) = delete;

        virtual operator Handle() const { return handle(); }

        virtual bool valid() const { return handle() != NullValue; }
		operator bool() const { return valid(); }

	protected:
        virtual Handle detach()
		{
			Handle ret = m_handle;
			if (!m_handle.compare_exchange_strong(ret, NullValue))
			{
			    if (m_handle != NullValue)
			    {
                    throw std::exception("Another thread changed the handle");
			    }
			}
			return ret;
		}

		virtual bool cleanup()
		{
			const auto handle = detach();
			if (handle != NullValue)
			{
				return Destructor(handle);
			}
			return false;
		}

        virtual HANDLE* unsafe_get_ptr()
		{
			static_assert(sizeof(decltype(m_handle)) == sizeof(HANDLE));
			return reinterpret_cast<HANDLE*>(&m_handle);
		}
	private:
		std::atomic<Handle> m_handle;
	};
}
