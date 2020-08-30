#pragma once
#include <string>
#include <WinBase.h>
#include "sys/safer/DefaultSafeHandle.hpp"

namespace maxisoft
{
	class InterProcessMutex {
	    using SafeHandle = ::maxisoft::utils::sys::safer::DefaultSafeHandle;
	private:
		static constexpr int GetOrCreateMutexMaxTries = 5;
	private:
		/**
		* @brief Actual mutex used by the system.
		*/
		SafeHandle m_;

		inline static HANDLE GetOrCreateMutex(const std::wstring& name);

		inline static std::wstring GetErrorAsString()
		{
			return GetErrorAsString(::GetLastError());
		}

		static std::wstring GetErrorAsString(DWORD errorMessageID);

	public:
		/**
		* @brief Constructor.
		*/
		explicit InterProcessMutex(const std::wstring& name);

		InterProcessMutex(const InterProcessMutex& other) = delete;

		InterProcessMutex(InterProcessMutex&& other) noexcept;


		bool valid() const;

		/**
		* @brief Attempts to lock the mutex.
		*/
		bool try_lock();

		/**
		* @brief Locks the mutex.
		*/
		void lock();

		/**
		* @brief Unlocks the mutex.
		*/
		void unlock();
	};
}
