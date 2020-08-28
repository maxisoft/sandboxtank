#pragma once

#include <string>
#include <utility>
#include <vector>
#include <sstream>
#include <map>
#include <unordered_map>
#include <optional>

#include <nlohmann/json.hpp>

#include "../../windows_include.hpp"
#include "../../utils/StringUtils.h"
#include "../../hash/hash.hpp"

#include "FlagParser.hpp"

namespace maxisoft::sandbox::config
{

    extern FlagParser<DWORD> job_object_uilimit;
    extern FlagParser<std::string> integrity_flags;
    extern FlagParser<std::string> se_privileges;
    extern FlagParser<DWORD64> proc_crea_policy_flags;


    class Config
    {
    public:
        bool disable_admin;
        bool disable_subprocess_spawn;
        bool fake_parent_process;
        std::string raw_integrity_level;
        std::vector<std::string> raw_se_privileges;
        std::vector<std::string> raw_proc_thread_attribute_mitigation_policy;
        std::string user_name;
        std::string password;
        bool resume_subprocess;
        bool wait_stdin;
    public:
        explicit Config() : disable_admin(true), disable_subprocess_spawn(true), fake_parent_process(true),
                            raw_integrity_level("medium"),
                            raw_se_privileges({
                                              "CREATE_TOKEN_NAME",
                                              "ASSIGNPRIMARYTOKEN_NAME",
                                              "LOCK_MEMORY_NAME",
                                              "INCREASE_QUOTA_NAME",
                                              "MACHINE_ACCOUNT_NAME",
                                              "TCB_NAME",
                                              "SECURITY_NAME",
                                              "TAKE_OWNERSHIP_NAME",
                                              "LOAD_DRIVER_NAME",
                                              "SYSTEM_PROFILE_NAME",
                                              "SYSTEMTIME_NAME",
                                              "PROF_SINGLE_PROCESS_NAME",
                                              "INC_BASE_PRIORITY_NAME",
                                              "CREATE_PAGEFILE_NAME",
                                              "CREATE_PERMANENT_NAME",
                                              "BACKUP_NAME",
                                              "RESTORE_NAME",
                                              "SHUTDOWN_NAME",
                                              "DEBUG_NAME",
                                              "AUDIT_NAME",
                                              //"SYSTEM_ENVIRONMENT_NAME",
                                              //"CHANGE_NOTIFY_NAME",
                                              "REMOTE_SHUTDOWN_NAME",
                                              "UNDOCK_NAME",
                                              "SYNC_AGENT_NAME",
                                              "ENABLE_DELEGATION_NAME",
                                              "MANAGE_VOLUME_NAME",
                                              "IMPERSONATE_NAME",
                                              "CREATE_GLOBAL_NAME",
                                              "TRUSTED_CREDMAN_ACCESS_NAME",
                                              "RELABEL_NAME",
                                              //"INC_WORKING_SET_NAME",
                                              "TIME_ZONE_NAME",
                                              //"CREATE_SYMBOLIC_LINK_NAME",
                                              "DELEGATE_SESSION_USER_IMPERSONATE_NAME"}),
                            resume_subprocess(true),
                            wait_stdin(false)
        {

        }

        class JobConfig
        {
        public:
            bool use_job;
            bool inherit_handle;
            std::string name;
            size_t num_process_in_job;
            int priority;
            bool kill_on_job_close;
            bool die_on_unhandled_exception;
            std::vector<std::string> ui_restrictions;
            double cpu_rate_percent;
        public:
            explicit JobConfig() : use_job(true), inherit_handle(false), name(), num_process_in_job(1),
                                   priority(NORMAL_PRIORITY_CLASS), kill_on_job_close(false),
                                   die_on_unhandled_exception(true),
                                   ui_restrictions{{"DESKTOP", "DISPLAYSETTINGS", "EXITWINDOWS", "GLOBALATOMS", "HANDLES", "SYSTEMPARAMETERS"}},
                                   cpu_rate_percent(78)
            {
            }

            std::vector<DWORD> ui_restriction_flags() const
            {
                return job_object_uilimit.parse(std::cbegin(ui_restrictions), std::cend(ui_restrictions));
            }
        };

    public:
        const JobConfig &job_config() const
        {
            return m_job_config;
        }

        void set_job_config(const JobConfig &job_config)
        {
            m_job_config = job_config;
        }

        void set_job_config(JobConfig &&job_config)
        {
            m_job_config = job_config;
        }

        std::string integrity_level() const
        {
            auto r = integrity_flags.parse(raw_integrity_level);
            return r.value_or("S-1-16-8192");
        }

        std::vector<std::string> se_privileges() const
        {
            return ::maxisoft::sandbox::config::se_privileges.parse(std::cbegin(raw_se_privileges), std::cend(raw_se_privileges));
        }

        std::vector<DWORD64> proc_thread_attribute_mitigation_policy() const
        {
            return proc_crea_policy_flags.parse(std::cbegin(raw_proc_thread_attribute_mitigation_policy),
                                                std::cend(raw_proc_thread_attribute_mitigation_policy));
        }

    private:
        JobConfig m_job_config;
    };


    inline void to_json(nlohmann::json &j, const Config::JobConfig &config)
    {
#define PUSH_JSON_PROPERTY(x) {(#x), (config.x)}
        j = nlohmann::json{
                PUSH_JSON_PROPERTY(use_job),
                PUSH_JSON_PROPERTY(inherit_handle),
                PUSH_JSON_PROPERTY(name),
                PUSH_JSON_PROPERTY(num_process_in_job),
                PUSH_JSON_PROPERTY(priority),
                PUSH_JSON_PROPERTY(kill_on_job_close),
                PUSH_JSON_PROPERTY(die_on_unhandled_exception),
                PUSH_JSON_PROPERTY(ui_restrictions),
                PUSH_JSON_PROPERTY(cpu_rate_percent)
        };
#undef PUSH_JSON_PROPERTY
    }

    inline void from_json(const nlohmann::json &j, Config::JobConfig &config)
    {
#define GET_JSON_VALUE(x) if (j.find(#x) != j.end()) config.x = j.at(#x).get<decltype(config.x)>()
        GET_JSON_VALUE(use_job);
        GET_JSON_VALUE(inherit_handle);
        GET_JSON_VALUE(name);
        GET_JSON_VALUE(num_process_in_job);
        GET_JSON_VALUE(priority);
        GET_JSON_VALUE(kill_on_job_close);
        GET_JSON_VALUE(die_on_unhandled_exception);
        GET_JSON_VALUE(ui_restrictions);
        GET_JSON_VALUE(cpu_rate_percent);
#undef GET_JSON_VALUE
    }

    inline void to_json(nlohmann::json &j, const Config &config)
    {
#define PUSH_JSON_PROPERTY(x) {(#x), (config.x)}
        j = nlohmann::json{
                PUSH_JSON_PROPERTY(disable_admin),
                PUSH_JSON_PROPERTY(disable_subprocess_spawn),
                PUSH_JSON_PROPERTY(fake_parent_process),
                PUSH_JSON_PROPERTY(raw_integrity_level),
                PUSH_JSON_PROPERTY(raw_se_privileges),
                PUSH_JSON_PROPERTY(raw_proc_thread_attribute_mitigation_policy),
                PUSH_JSON_PROPERTY(user_name),
                PUSH_JSON_PROPERTY(password),
                PUSH_JSON_PROPERTY(resume_subprocess),
                PUSH_JSON_PROPERTY(wait_stdin),
                {"job_config", config.job_config()}
        };
#undef PUSH_JSON_PROPERTY
    }

    inline void from_json(const nlohmann::json &j, Config &config)
    {
#define GET_JSON_VALUE(x) if (j.find(#x) != j.end()) config.x = j.at(#x).get<decltype(config.x)>()
        GET_JSON_VALUE(disable_admin);
        GET_JSON_VALUE(disable_subprocess_spawn);
        GET_JSON_VALUE(fake_parent_process);
        GET_JSON_VALUE(raw_integrity_level);
        GET_JSON_VALUE(raw_se_privileges);
        GET_JSON_VALUE(raw_proc_thread_attribute_mitigation_policy);
        GET_JSON_VALUE(user_name);
        GET_JSON_VALUE(password);
        GET_JSON_VALUE(resume_subprocess);
        GET_JSON_VALUE(wait_stdin);
        if (j.find("job_config") != j.end()) config.set_job_config(j.at("job_config").get<Config::JobConfig>());
#undef GET_JSON_VALUE
    }

}