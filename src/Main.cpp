#include <cstdio>
#include <tchar.h>
#include <vector>
#include <Windows.h>
#include <UserEnv.h>
#include <iostream>
#include <Psapi.h>
#include <sddl.h>
#include <atomic>
#include <functional>
#include <winsafer.h>
#include <TlHelp32.h>
#include <map>
#include <optional>
#include <array>
#include <filesystem>
#include <mutex>
#include <fstream>

#include "utils/__all__.hpp"
#include <thread>
#include <cassert>
#include "sandbox/config/Config.hpp"
#include "utils/StringUtils.h"
#include "sandbox/JobProcess.hpp"
#include "sandbox/TokenProcess.hpp"
#include "DesktopACL.h"
#include "sandbox/SharedMemory.hpp"
#include "sandbox/TokenProcess.hpp"
#include "../cpp-mmf/memory_mapped_file.hpp"
#include "sandbox/Globals.hpp"
#include "sandbox/ProgramArgs.hpp"
#include "sandbox/JobProcess.hpp"

void ThrowForNativeCallError(LPWSTR pszAPI, UINT codepage = CP_UTF8)
{
	LPVOID lpvMessageBuffer;

	auto res = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
	              FORMAT_MESSAGE_FROM_SYSTEM,
	              nullptr, GetLastError(),
	              0,
	              (LPWSTR)&lpvMessageBuffer, 0, nullptr);

	if (res <= 0)
	{
		res = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM,
			nullptr, GetLastError(),
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPWSTR)&lpvMessageBuffer, 0, nullptr);
	}

	std::wstringstream ss{};
	ss << pszAPI << L" err(" << GetLastError() << ")";
	if (res > 0)
	{
		ss << " :" << maxisoft::utils::trim(std::wstring_view(reinterpret_cast<LPWSTR>(lpvMessageBuffer), res));
	}

	LocalFree(lpvMessageBuffer);
	const auto s = maxisoft::utils::ws2s(ss.str(), codepage);
	throw std::exception(s.c_str());
}




BOOL CALLBACK EnumWindowsProc(
	_In_	     HWND hwnd,
	    	     _In_	     LPARAM lParam
)
{
    thread_local std::wstring windowtextbuff = std::wstring(255, wchar_t(0));
	auto r = GetWindowText(hwnd, windowtextbuff.data(), static_cast<int>(windowtextbuff.capacity()));
	if (r && lParam)
		*reinterpret_cast<size_t*>(lParam) += 1;
	return true;
}


void PrintProcessNameAndID(DWORD processID)
{
	TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

	// Get a handle to the process.

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
	                              PROCESS_VM_READ,
	                              FALSE, processID);

	// Get the process name.

	if (nullptr != hProcess)
	{
		HMODULE hMod;
		DWORD cbNeeded;

		if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
		                       &cbNeeded))
		{
			GetModuleBaseName(hProcess, hMod, szProcessName,
			                  sizeof(szProcessName) / sizeof(TCHAR));
		}
	}

	// Print the process name and identifier.

	_tprintf(TEXT("%s  (PID: %u)\n"), szProcessName, processID);

	// Release the handle to the process.

	CloseHandle(hProcess);
}

using namespace maxisoft::utils::sys::safer;
struct ProcessContext
{


	DWORD pid;
    ProcessHandle target_process_handle;
	ProcessHandle explorer_handle;
    ProcessHandle injected_parent_process;
	std::array<wchar_t, 255> user_sid;

	explicit ProcessContext() = default;
	ProcessContext(const ProcessContext&) = delete;

	ProcessContext(ProcessContext&& other) noexcept : pid(other.pid),
	                                                  target_process_handle(std::move(other.target_process_handle)),
	                                                  explorer_handle(std::move(other.explorer_handle)),
	                                                  injected_parent_process(std::move(other.injected_parent_process)),
	                                                  user_sid(other.user_sid)
	{
		other.cleanup();
	}

    [[noreturn]] void cleanup()
	{
		if (pid == GetCurrentProcessId())
		{
            for (DefaultSafeHandle& h : {std::ref(target_process_handle),
                                         std::ref(explorer_handle),
                                         std::ref(injected_parent_process)}) {
                h.cleanup();
            }
		}
		else
        {
            for (DefaultSafeHandle& h : {std::ref(target_process_handle),
                                         std::ref(explorer_handle),
                                         std::ref(injected_parent_process)}) {
                h.detach();
            }
        }
	}

	~ProcessContext()
	{
		cleanup();
	}

	ProcessContext& operator=(ProcessContext&& other) noexcept
	{
		cleanup();
		pid = other.pid;
		target_process_handle = std::move(other.target_process_handle);
		explorer_handle = std::move(other.explorer_handle);
		injected_parent_process = std::move(other.injected_parent_process);
		other.cleanup();
		return *this;
	}
};

struct SharedMemData
{
	using MagicArray = std::array<char, 20>;
	MagicArray magic;
	std::array<char, 65535> config;
	uint64_t config_key;
	size_t config_length;
	DWORD time;
	DWORD main_process;
	uint64_t build_date_hash;
	std::array<ProcessContext, 2> contexts;
	std::array<char, 2048> error;

	ProcessContext& get_current_context()
	{
		if (auto ctx = get_context(GetCurrentProcessId()))
		{
			return *ctx;
		}
		throw std::exception("unable to get current context");
	}

	std::optional<std::reference_wrapper<ProcessContext>> get_context(const DWORD pid)
	{
		for (auto& context : contexts)
		{
			if (context.pid == pid)
			{
				return std::ref(context);
			}
		}
		return {};
	}

	explicit SharedMemData() : magic(s_magic_array),
	                                                config(), config_key(), config_length(), time(),
	                                                main_process(0),
	                                                build_date_hash(s_build_date_hash), contexts(),
													error()
	{
	}

	bool valid() const
	{
		return magic == s_magic_array && build_date_hash == s_build_date_hash && config_length <= config.size();
	}

private:
	static constexpr uint64_t s_build_date_hash = maxisoft::hash::hash64(__TIMESTAMP__);
	static constexpr MagicArray s_magic_array = {'A', 'P', 'P', 'S', 'A', 'N', 'D', 'B', 'O', 'X', '1'};
};

constexpr uint64_t _BaseKey = uint64_t(__COUNTER__) ^ maxisoft::hash::hash64(__COUNTER__) ^ maxisoft::hash::
	hash64(__TIMESTAMP__);

template <typename T, uint64_t BaseKey = static_cast<uint64_t>(_BaseKey)>
class XorCipher
{
public:
	using type = std::enable_if_t<std::is_integral_v<T>, T>;

	explicit XorCipher(const uint64_t key) : key_(key), counter_(0)
	{
	}

	type operator()(const type x)
	{
		return static_cast<type>((BaseKey + maxisoft::hash::hash64(counter_++) + key_) ^ x);
	}

private:
	uint64_t key_;
	std::atomic_size_t counter_;
};


using SharedMemory = ::maxisoft::sandbox::SharedMemory<SharedMemData>;
using maxisoft::sandbox::globals;

static std::unique_ptr<SharedMemory> InitSharedMemory(std::wstring id)
{

    using maxisoft::hash::hash64;
	auto shared_memory = std::make_unique<SharedMemory>(id);
	SharedMemory& shmem = std::ref(*shared_memory.get());
	SharedMemData& data = *shmem.data();
	nlohmann::json j = globals.config();

	if (data.main_process <= 0)
	{
		auto lock = shmem.get_lock();
		if (data.main_process <= 0)
		{
			const auto config_str = j.dump();
			assert(config_str.size() <= data.config.size());
			auto id = maxisoft::utils::GenerateUUID();
			static_assert(sizeof(id.Data4) == sizeof(int64_t));
			const uint64_t key = hash64(id.Data1) * 331 + hash64(id.Data2) * 331 + hash64(id.Data3) * 331 + hash64(
					*reinterpret_cast<int64_t*>(id.Data4));
			std::transform(std::cbegin(config_str), std::cend(config_str), data.config.begin(),
			               XorCipher<char>(key));


			data.main_process = GetCurrentProcessId();
			data.time = GetTickCount();
			data.config_length = config_str.size();
			data.config_key = key;
			data.contexts.at(0).pid = GetCurrentProcessId();
			if (const auto explorer_process = ::maxisoft::utils::sys::GetExplorerProcess())
			{
				DuplicateHandle(globals.process(), explorer_process.handle(), globals.process(),
				                data.contexts.at(0).explorer_handle.unsafe_get_ptr(), 0, false, DUPLICATE_SAME_ACCESS);
			}
			const auto def_token = maxisoft::sandbox::get_default_token(TOKEN_QUERY | TOKEN_READ | TOKEN_QUERY_SOURCE);
			auto sid = maxisoft::sandbox::ObtainUserSidString(*def_token);
			wcsncpy_s(data.contexts.at(0).user_sid.data(), data.contexts.at(0).user_sid.size(), sid.data(), sid.size());

			shmem.flush();
			assert(data.valid());
		}
	}

	return shared_memory;
}

static void InitAsChildProcess(SharedMemory& shared_memory)
{
    using Config = ::maxisoft::sandbox::Config;
	auto lock = shared_memory.get_lock();
	SharedMemData& data = std::ref(*shared_memory.data());
	if (!data.valid())
	{
		throw std::exception("shared memory data is invalid");
	}
	if (data.main_process == GetCurrentProcessId())
	{
		throw std::exception("trying to init parent process as child");
	}
	const uint64_t key = data.config_key;
	std::string config_str(data.config_length, char(0));
	std::transform(data.config.begin(), data.config.begin() + data.config_length, config_str.data(),
	               XorCipher<char>(key));
	nlohmann::json j = config_str;

	globals.set_config(j.get<Config>());
	if (const auto explorer_process = ::maxisoft::utils::sys::GetExplorerProcess())
	{
		if (data.get_current_context().explorer_handle)
		{
			CloseHandle(data.get_current_context().explorer_handle);
		}
		if (!DuplicateHandle(globals.process(), explorer_process.handle(), globals.process(),
		                     data.get_current_context().explorer_handle.unsafe_get_ptr(), 0, false,
		                     DUPLICATE_SAME_ACCESS))
		{
			data.get_current_context().explorer_handle.cleanup();
		}
	}
	shared_memory.flush();
}


static void ResumeProcess(HANDLE processHandle)
{
	typedef LONG (NTAPI *NtResumeProcessProc)(IN HANDLE ProcessHandle);
	auto NtSuspendProcess = reinterpret_cast<NtResumeProcessProc>(GetProcAddress(
		GetModuleHandle(TEXT("ntdll")), "NtResumeProcess"));
	if (NtSuspendProcess == nullptr)
	{
		throw std::exception("unable to get NtResumeProcess proc");
	}
	NtSuspendProcess(processHandle);
}

int ForkAndContinueAsUser(const maxisoft::sandbox::ProgramArgs& args, SharedMemory& shared_memory, std::wstring user,
                          std::wstring password, std::wstring domain)
{
    using TokenHandle = ::maxisoft::utils::sys::safer::TokenHandle;
	TokenHandle usertoken{};
	PROCESS_INFORMATION pi = { 0 };
	try
	{
		if (LogonUserW(user.c_str(), domain.empty() ? nullptr : domain.c_str(),
			password.empty() ? nullptr : password.c_str(),
			LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, usertoken.unsafe_get_ptr()))
		{
			STARTUPINFO si = { 0 };
			si.cb = sizeof(STARTUPINFO);

			PSID psid = nullptr;
			if (!maxisoft::sandbox::ObtainSid(usertoken, &psid))
			{
				throw std::exception("unable to get sid");
			}


			auto hdesk = OpenDesktop(
				TEXT("default"),
				0,
				FALSE,
				READ_CONTROL | WRITE_DAC |
				DESKTOP_WRITEOBJECTS | DESKTOP_READOBJECTS
			);
			if (hdesk)
			{
				maxisoft::sandbox::AddTheAceDesktop(hdesk, psid);
			}

			HWINSTA hwinsta = GetProcessWindowStation();
			if (hwinsta)
			{
				maxisoft::sandbox::AddTheAceWindowStation(hwinsta, psid);
			}

			const DWORD additionalFlags = globals.is_process_in_job() ? CREATE_BREAKAWAY_FROM_JOB : 0;
			si.lpDesktop = nullptr;
			if (!CreateProcessWithLogonW(user.c_str(), domain.empty() ? nullptr : domain.c_str(),
				password.empty() ? nullptr : password.c_str(),
				LOGON_WITH_PROFILE, args.program.c_str(), args.to_child_args(true).data(),
				CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED | CREATE_NO_WINDOW | additionalFlags,
				nullptr,
				nullptr,
				reinterpret_cast<STARTUPINFO*>(&si), &pi))
			{
				ThrowForNativeCallError(L"CreateProcessWithLogonW");
			}

			{
				auto lock = shared_memory.get_lock();
				auto& sub_context = shared_memory.data()->contexts.at(1);
				sub_context.pid = pi.dwProcessId;
				auto sid = maxisoft::sandbox::ObtainUserSidString(usertoken);
				wcsncpy_s(sub_context.user_sid.data(), sub_context.user_sid.size(), sid.data(), sid.size());
				PSID usersid = nullptr;
				ConvertStringSidToSidW(sub_context.user_sid.data(), &usersid);

				const auto explorer_process = ::maxisoft::utils::sys::GetExplorerProcess();
				if (explorer_process &&
					maxisoft::sandbox::AddTheAceProcess(explorer_process, usersid) &&
					!DuplicateHandle(globals.process(), explorer_process, pi.hProcess,
						sub_context.explorer_handle.unsafe_get_ptr(), 0, false, DUPLICATE_SAME_ACCESS))
				{
					throw std::exception("unable to duplicate explorer process");
				}

				PSID tpsid = nullptr;
				if (ConvertStringSidToSidW(shared_memory.data()->contexts.at(0).user_sid.data(), &tpsid) && tpsid)
				{
					maxisoft::sandbox::AddTheAceProcess(pi.hProcess, tpsid);
				}
				LocalFree(tpsid);

				if (!maxisoft::sandbox::AddTheAceProcess(globals.process(), usersid) ||
					!DuplicateHandle(globals.process(), globals.process(), pi.hProcess,
						sub_context.injected_parent_process.unsafe_get_ptr(), 0, false, DUPLICATE_SAME_ACCESS))
				{
					throw std::exception("unable to duplicate current process");
				}
				shared_memory.flush();
				if (usersid)
				{
					LocalFree(usersid);
				}
			}

			CloseWindowStation(hwinsta);
			CloseDesktop(hdesk);
			maxisoft::sandbox::RemoveSid(&psid);
			ResumeThread(pi.hThread);
			if (WaitForSingleObject(pi.hProcess, 50 * 1000) != WAIT_OBJECT_0)
			{
				throw std::exception("subprocess wait timeout");
			}

			DWORD exit_code;
			if (!GetExitCodeProcess(pi.hProcess, &exit_code))
			{
				ThrowForNativeCallError(L"GetExitCodeProcess");
			}

			if (exit_code == STILL_ACTIVE)
			{
				throw std::exception("subprocess wait timeout");
			}

			if (exit_code != EXIT_SUCCESS)
			{
				throw std::exception("forked process crashed");
			}

			const auto& target_process = shared_memory.data()->get_current_context().target_process_handle;

			nlohmann::json out;
			out["resumed"] = false;
			if (globals.config().wait_stdin)
			{
				std::cin.get();
			}
			if (globals.config().resume_subprocess)
			{
				ResumeProcess(target_process);
				out["resumed"] = true;
			}

			out["SID"] = maxisoft::utils::ws2s(shared_memory.data()->contexts.at(1).user_sid.data(),
				wcsnlen(shared_memory.data()->contexts.at(1).user_sid.data(),
					shared_memory.data()->contexts.at(1).user_sid.size()), CP_UTF8);
			out["process"] = GetProcessId(target_process);
			out["in_job"] = globals.is_process_in_job(target_process);
			out["session"] = maxisoft::utils::ws2s(args.sessionid.value_or(L"<invalid>"), CP_UTF8);
			out["program"] = maxisoft::utils::ws2s(args.additional_args.front(), CP_UTF8);
			std::cout << out.dump() << std::endl;
			std::cout << std::flush;
			return EXIT_SUCCESS;
		}
		throw std::exception("unable to login using provided credential");
	}
	catch (std::exception&)
	{
		if (shared_memory.data()->get_current_context().target_process_handle)
		{
			auto lock = shared_memory.get_lock();
			if (auto& p = shared_memory.data()->get_current_context().target_process_handle)
			{
				TerminateProcess(p, EXIT_FAILURE);
				p.cleanup();
				shared_memory.flush();
			}
		}
		if (pi.hProcess)
		{
			TerminateProcess(pi.hProcess, EXIT_FAILURE);
		}
		throw;
	}
}

int wmain(int argc, wchar_t* argv[], wchar_t* envp[])
{
    using namespace maxisoft::utils::sys::safer;
    using Config = ::maxisoft::sandbox::Config;
	SAFE_PROCESS_INFORMATION process_information{};
	maxisoft::sandbox::ProgramArgs args{};
	std::unique_ptr<SharedMemory> shared_memory;
	try
	{
		args = maxisoft::sandbox::ProgramArgs::parse_args(argc, argv);

		if (args.additional_args.empty())
		{
			throw std::exception("invalid application arguments");
		}
		if (!exists(std::filesystem::path(args.additional_args.front())))
		{
			throw std::exception("invalid target application");
		}

		if (!args.config.empty())
		{
			nlohmann::json j;
			std::ifstream cfgfile{};
			cfgfile.open(args.config);
			cfgfile >> j;
			globals.set_config(j.get<Config>());
		}

		auto guid = args.sessionid ? *args.sessionid : maxisoft::utils::UUIDToString(maxisoft::utils::GenerateUUID());

		shared_memory = InitSharedMemory(guid);
		SharedMemData& data = std::ref(*shared_memory->data());

		const bool is_main_process = data.main_process == GetCurrentProcessId();

		if (!is_main_process)
		{
			InitAsChildProcess(std::ref(*shared_memory));
		}
		else
		{
			std::wstring user = args.user ? *args.user : maxisoft::utils::s2ws(globals.config().user_name);
			if (!user.empty())
			{
				std::wstring password = args.password
					                        ? *args.password
					                        : maxisoft::utils::s2ws(globals.config().password);
				std::wstring domain = args.domain ? *args.domain : std::wstring{};
				args.sessionid = guid;
				return ForkAndContinueAsUser(args, std::ref(*shared_memory), user, password, domain);
			}
		}

		{
			const auto& explorer_process = data.get_current_context().explorer_handle;
			DWORD process_id = explorer_process ? GetProcessId(explorer_process) : 0;

			const auto attribute_list = SAFER_LPPROC_THREAD_ATTRIBUTE_LIST::create(globals.config(), explorer_process);
			const auto token = maxisoft::sandbox::create_token(globals.config());
			const auto job = maxisoft::sandbox::create_job(globals.config(), *token);

			STARTUPINFOEX si = {0};
			si.StartupInfo.cb = sizeof(decltype(si));
			if (attribute_list)
			{
				si.lpAttributeList = *attribute_list;
			}

			const DWORD additionalFlags = globals.is_process_in_job() && is_main_process
				                              ? CREATE_BREAKAWAY_FROM_JOB
				                              : 0;

			PROCESS_INFORMATION pi;
			PSID tpsid = nullptr;
			ConvertStringSidToSidW(data.contexts.at(0).user_sid.data(), &tpsid);

			const auto cwd = args.working_directory.empty()
				                 ? std::filesystem::path(args.additional_args.front()).parent_path()
				                 : args.working_directory;

			if (!CreateProcessAsUser(*token, args.additional_args.front().c_str(), args.to_child_args(false).data(),
			                         nullptr, nullptr, FALSE,
			                         CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_DEFAULT_ERROR_MODE | additionalFlags,
			                         nullptr, absolute(cwd).c_str(),
			                         reinterpret_cast<STARTUPINFO*>(&si), &pi))
			{
				ThrowForNativeCallError(L"CreateProcessAsUser");
			}

			process_information = std::move(pi);

			if (tpsid && !maxisoft::sandbox::AddTheAceProcess(process_information.hProcess, tpsid))
			{
				ThrowForNativeCallError(L"AddTheAceProcess");
			}

			if (!is_main_process)
			{
				HANDLE tmp;
				if (!DuplicateHandle(globals.process(), process_information.hProcess,
				                     data.get_current_context().injected_parent_process, &tmp, 0, false,
				                     DUPLICATE_SAME_ACCESS))
				{
					throw std::exception("DuplicateHandle");
				}
				auto lock = shared_memory->get_lock();
				data.contexts[0].target_process_handle = tmp;
				shared_memory->flush();
			}

			if (tpsid)
			{
				LocalFree(tpsid);
			}

			if (job && !AssignProcessToJobObject(job, process_information.hProcess))
			{
				ThrowForNativeCallError(L"AssignProcessToJobObject");
			}
		}

		nlohmann::json out;
		out["resumed"] = false;
		out["SID"] = maxisoft::utils::ws2s(shared_memory->data()->get_current_context().user_sid.data(),
			wcsnlen(shared_memory->data()->get_current_context().user_sid.data(),
				shared_memory->data()->get_current_context().user_sid.size()), CP_UTF8);

		if (globals.config().wait_stdin && is_main_process)
		{
			std::cin.get();
		}
		if (globals.config().resume_subprocess)
		{
			const auto resumed = ResumeThread(process_information.hThread);
			if (resumed == 1)
			{
				out["resumed"] = true;
			}
			else if (resumed == static_cast<DWORD>(-1))
			{
				TerminateProcess(process_information.hProcess, EXIT_FAILURE);
				throw std::exception("process gets killed");
			}
		}
		out["process"] = GetProcessId(process_information.hProcess);
		out["in_job"] = globals.is_process_in_job(process_information.hProcess);
		out["session"] = maxisoft::utils::ws2s(guid, CP_UTF8);
		out["program"] = maxisoft::utils::ws2s(args.additional_args.front(), CP_UTF8);
		if (is_main_process)
		{
			std::cout << out.dump() << std::endl;
		}
		else
		{
			std::cout << std::flush;
		}
		shared_memory->data()->error.front() = 0;
		return EXIT_SUCCESS;
	}
	catch (std::exception& e)
	{	
		nlohmann::json out;
		out["error"] = true;
		out["message"] = e.what() ? e.what() : "";
#if _DEBUG
		out["debug"] = true;
#endif
		std::optional<std::string> playload;
		if (shared_memory)
		{
			auto lock = shared_memory->get_lock();

			if (shared_memory->data())
			{
				if (*shared_memory->data()->error.data())
				{
					try
					{
						nlohmann::json inner = nlohmann::json::parse(std::string_view(shared_memory->data()->error.data(),
							strnlen(shared_memory->data()->error.data(), shared_memory->data()->error.size())));
						auto it = inner.find("message");
						if (it != inner.end())
						{
							out["sub_message"] = it->get<std::string>();
						}
						else if (!inner.empty())
						{
							out["sub_message"] = inner;
						}
						else
						{
							out["sub_message"] = std::string_view(shared_memory->data()->error.data(),
								strnlen(shared_memory->data()->error.data(), shared_memory->data()->error.size()));
						}
					}
					catch (std::exception&)
					{
						out["sub_message"] = "<invalid>";
					}
				}
				else
				{
					try
					{
						playload = out.dump();
						std::copy(playload->cbegin(), playload->cend(), shared_memory->data()->error.begin());
					}
					catch (...)
					{
#if _DEBUG
						throw;
#endif
					}
				}
			}
			shared_memory->flush();
		}
		if (process_information.hProcess)
		{
			TerminateProcess(process_information.hProcess, EXIT_FAILURE);
		}
		try
		{
			std::cout << (playload ? *playload : out.dump()) << std::endl;
		}
		catch (...)
		{
			std::cout << R"({"error": true, "message": "fatal"})" << std::endl;
#if _DEBUG
			throw;
#endif
		}
		
#if _DEBUG
		throw;
#endif
		return EXIT_FAILURE;
	}
	return EXIT_FAILURE;
}
