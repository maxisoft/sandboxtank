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
#include "../../utils/StringUtils.hpp"
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
        explicit Config();

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
            explicit JobConfig();

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


    void to_json(nlohmann::json &j, const Config::JobConfig &config);

    void from_json(const nlohmann::json &j, Config::JobConfig &config);

    void to_json(nlohmann::json &j, const Config &config);

    void from_json(const nlohmann::json &j, Config &config);

}