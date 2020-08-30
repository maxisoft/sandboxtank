#include "JobProcess.hpp"

namespace maxisoft::sandbox
{
    JobHandle create_job(const Config &config, const TokenHandle &jobtoken)
    {
        using maxisoft::utils::s2ws;
        const auto &job_config = config.job_config();
        if (!job_config.use_job) return {};
        SECURITY_ATTRIBUTES security = {0};
        if (job_config.inherit_handle)
        {
            security.bInheritHandle = job_config.inherit_handle;
            security.lpSecurityDescriptor = nullptr;
            security.nLength = sizeof(decltype(security));
        }

        auto handle = CreateJobObject(job_config.inherit_handle ? &security : nullptr,
                                      job_config.name.empty() ? nullptr : maxisoft::utils::s2ws(
                                              job_config.name).c_str());
        if (!handle)
        {
            return {};
        }

        JOBOBJECT_EXTENDED_LIMIT_INFORMATION extended_limit = {0};
        auto &basic_limit = extended_limit.BasicLimitInformation;
        if (job_config.num_process_in_job > 0 || config.disable_subprocess_spawn)
        {
            basic_limit.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            basic_limit.ActiveProcessLimit = static_cast<DWORD>(job_config.num_process_in_job);
        }
        if (job_config.priority > 0)
        {
            basic_limit.LimitFlags |= JOB_OBJECT_LIMIT_PRIORITY_CLASS;
            basic_limit.PriorityClass = NORMAL_PRIORITY_CLASS;
        }
        if (job_config.kill_on_job_close)
        {
            basic_limit.LimitFlags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        }
        if (job_config.die_on_unhandled_exception)
        {
            basic_limit.LimitFlags |= JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        }


        BOOL res = true;
        if (basic_limit.LimitFlags != 0)
        {
            res = SetInformationJobObject(handle, JobObjectExtendedLimitInformation, &extended_limit,
                                          sizeof(decltype(extended_limit)));
            if (res == FALSE)
            {
                throw std::exception("unable to set JobObjectExtendedLimitInformation");
            }
        }

        JOBOBJECT_BASIC_UI_RESTRICTIONS ui_restrictions = {0};

        auto ui_restriction_flags = job_config.ui_restriction_flags();
        for (const auto &flag : ui_restriction_flags)
        {
            ui_restrictions.UIRestrictionsClass |= flag;
        }

        if (ui_restrictions.UIRestrictionsClass != 0)
        {
            res = SetInformationJobObject(handle, JobObjectBasicUIRestrictions, &ui_restrictions,
                                          sizeof(decltype(ui_restrictions)));
            if (res == FALSE)
            {
                throw std::exception("unable to set JobObjectBasicUIRestrictions");
            }
        }


        JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpu_rate_control = {0};
        if (isnormal(job_config.cpu_rate_percent) && job_config.cpu_rate_percent > 0)
        {
            cpu_rate_control.ControlFlags |= JOB_OBJECT_CPU_RATE_CONTROL_ENABLE;
            cpu_rate_control.ControlFlags |= JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
            cpu_rate_control.CpuRate = static_cast<DWORD>(job_config.cpu_rate_percent * 100);
        }

        if (cpu_rate_control.ControlFlags != 0 && cpu_rate_control.CpuRate > 0)
        {
            res = SetInformationJobObject(handle, JobObjectCpuRateControlInformation, &cpu_rate_control,
                                          sizeof(decltype(cpu_rate_control)));
            if (res == FALSE)
            {
                throw std::exception("unable to set JobObjectCpuRateControlInformation");
            }
        }

        if (config.disable_admin)
        {
            JOBOBJECT_SECURITY_LIMIT_INFORMATION security_limit = {0};
            security_limit.SecurityLimitFlags |= JOB_OBJECT_SECURITY_NO_ADMIN;
            if (jobtoken != nullptr)
            {
                security_limit.JobToken = jobtoken;
            }
            // ignore result
            SetInformationJobObject(handle, JobObjectSecurityLimitInformation, &security_limit,
                                    sizeof(decltype(security_limit)));
        }

        return static_cast<JobHandle>(handle);
    }
}