#include "Config.hpp"
#include <unordered_map>

#define _PUSH_FLAG_PROPERTY(x) {(#x), (x)}

namespace maxisoft::sandbox::config
{

FlagParser<DWORD> job_object_uilimit(
        {
            _PUSH_FLAG_PROPERTY(JOB_OBJECT_UILIMIT_HANDLES),
            _PUSH_FLAG_PROPERTY(JOB_OBJECT_UILIMIT_READCLIPBOARD),
            _PUSH_FLAG_PROPERTY(JOB_OBJECT_UILIMIT_WRITECLIPBOARD),
            _PUSH_FLAG_PROPERTY(JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS),
            _PUSH_FLAG_PROPERTY(JOB_OBJECT_UILIMIT_DISPLAYSETTINGS),
            _PUSH_FLAG_PROPERTY(JOB_OBJECT_UILIMIT_GLOBALATOMS),
            _PUSH_FLAG_PROPERTY(JOB_OBJECT_UILIMIT_DESKTOP),
            _PUSH_FLAG_PROPERTY(JOB_OBJECT_UILIMIT_EXITWINDOWS)
        },
        "JOB_OBJECT_UILIMIT_");


FlagParser<std::string> integrity_flags(
        {
            {"Untrusted", "S-1-16-0"},
            {"low",       "S-1-16-4096"},
            {"Medium",    "S-1-16-8192"},
            {"high",      "S-1-16-12288"},
            {"System",    "S-1-16-16384"},
            {"Protected", "S-1-16-20480"},
            {"Secure",    "S-1-16-28672"}
        },
        ""
);

#define _PUSH_SE_FLAG_PROPERTY(x) {(#x), (x)}
static_assert(sizeof(decltype(TEXT("A")[0])) == sizeof(wchar_t));

FlagParser<std::string> se_privileges(
    {
//Temporary replace TEXT macro
#pragma push_macro("TEXT")
#undef TEXT
#define TEXT(x) (x)
_PUSH_SE_FLAG_PROPERTY(SE_CREATE_TOKEN_NAME),
_PUSH_SE_FLAG_PROPERTY(SE_ASSIGNPRIMARYTOKEN_NAME),
_PUSH_SE_FLAG_PROPERTY(SE_LOCK_MEMORY_NAME),
_PUSH_SE_FLAG_PROPERTY(SE_INCREASE_QUOTA_NAME),
_PUSH_SE_FLAG_PROPERTY(SE_UNSOLICITED_INPUT_NAME),
_PUSH_SE_FLAG_PROPERTY(SE_MACHINE_ACCOUNT_NAME),
_PUSH_SE_FLAG_PROPERTY(SE_TCB_NAME),
_PUSH_SE_FLAG_PROPERTY(SE_SECURITY_NAME),
_PUSH_SE_FLAG_PROPERTY(SE_TAKE_OWNERSHIP_NAME),
_PUSH_SE_FLAG_PROPERTY(SE_LOAD_DRIVER_NAME),
_PUSH_SE_FLAG_PROPERTY(SE_SYSTEM_PROFILE_NAME),
_PUSH_SE_FLAG_PROPERTY(SE_SYSTEMTIME_NAME),
_PUSH_SE_FLAG_PROPERTY(SE_PROF_SINGLE_PROCESS_NAME),
_PUSH_SE_FLAG_PROPERTY(SE_INC_BASE_PRIORITY_NAME),
_PUSH_SE_FLAG_PROPERTY(SE_CREATE_PAGEFILE_NAME),
_PUSH_SE_FLAG_PROPERTY(SE_CREATE_PERMANENT_NAME),
_PUSH_SE_FLAG_PROPERTY(SE_BACKUP_NAME),
_PUSH_SE_FLAG_PROPERTY(SE_RESTORE_NAME),
_PUSH_SE_FLAG_PROPERTY(SE_SHUTDOWN_NAME),
_PUSH_SE_FLAG_PROPERTY(SE_DEBUG_NAME),
_PUSH_SE_FLAG_PROPERTY(SE_AUDIT_NAME),
_PUSH_SE_FLAG_PROPERTY(SE_SYSTEM_ENVIRONMENT_NAME),
_PUSH_SE_FLAG_PROPERTY(SE_CHANGE_NOTIFY_NAME),
_PUSH_SE_FLAG_PROPERTY(SE_REMOTE_SHUTDOWN_NAME),
_PUSH_SE_FLAG_PROPERTY(SE_UNDOCK_NAME),
_PUSH_SE_FLAG_PROPERTY(SE_SYNC_AGENT_NAME),
_PUSH_SE_FLAG_PROPERTY(SE_ENABLE_DELEGATION_NAME),
_PUSH_SE_FLAG_PROPERTY(SE_MANAGE_VOLUME_NAME),
_PUSH_SE_FLAG_PROPERTY(SE_IMPERSONATE_NAME),
_PUSH_SE_FLAG_PROPERTY(SE_CREATE_GLOBAL_NAME),
_PUSH_SE_FLAG_PROPERTY(SE_TRUSTED_CREDMAN_ACCESS_NAME),
_PUSH_SE_FLAG_PROPERTY(SE_RELABEL_NAME),
_PUSH_SE_FLAG_PROPERTY(SE_INC_WORKING_SET_NAME),
_PUSH_SE_FLAG_PROPERTY(SE_TIME_ZONE_NAME),
_PUSH_SE_FLAG_PROPERTY(SE_CREATE_SYMBOLIC_LINK_NAME),
_PUSH_SE_FLAG_PROPERTY(SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME)
    },
    "SE_"
#pragma pop_macro("TEXT")
);

FlagParser<DWORD64> proc_crea_policy_flags(
        {
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_DEP_ATL_THUNK_ENABLE),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_MASK),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_DEFER),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_ON),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_OFF),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_ON_REQ_RELOCS),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_MASK),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_DEFER),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_ALWAYS_ON),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_ALWAYS_OFF),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_RESERVED),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_MASK),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_DEFER),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_ON),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_OFF),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_RESERVED),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_MASK),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_DEFER),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_ON),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_OFF),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_RESERVED),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_MASK),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_DEFER),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_ALWAYS_ON),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_ALWAYS_OFF),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_RESERVED),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_MASK),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_DEFER),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_OFF),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_RESERVED),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_MASK),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_DEFER),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_OFF),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_RESERVED),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_MASK),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_DEFER),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_OFF),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON_ALLOW_OPT_OUT),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_MASK),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_DEFER),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_ON),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_OFF),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_EXPORT_SUPPRESSION),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_MASK),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_DEFER),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_OFF),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALLOW_STORE),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_FONT_DISABLE_MASK),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_FONT_DISABLE_DEFER),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_FONT_DISABLE_ALWAYS_ON),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_FONT_DISABLE_ALWAYS_OFF),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_AUDIT_NONSYSTEM_FONTS),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_MASK),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_DEFER),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_OFF),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_RESERVED),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_MASK),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_DEFER),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_OFF),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_RESERVED),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_MASK),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_DEFER),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_OFF),
_PUSH_FLAG_PROPERTY(PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_RESERVED),
        },
        "PROCESS_CREATION_MITIGATION_POLICY_"
);

    void to_json(nlohmann::json &j, const Config::JobConfig &config)
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

    void from_json(const nlohmann::json &j, Config::JobConfig &config)
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

    void to_json(nlohmann::json &j, const Config &config)
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

    void from_json(const nlohmann::json &j, Config &config)
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

    static_assert(sizeof(decltype(TEXT("A")[0])) == sizeof(wchar_t));

    Config::JobConfig::JobConfig() : use_job(true), inherit_handle(false), name(), num_process_in_job(1),
                                     priority(NORMAL_PRIORITY_CLASS), kill_on_job_close(false),
                                     die_on_unhandled_exception(true),
                                     ui_restrictions{{"DESKTOP", "DISPLAYSETTINGS", "EXITWINDOWS", "GLOBALATOMS", "HANDLES", "SYSTEMPARAMETERS"}},
                                     cpu_rate_percent(78)
    {
    }

    Config::Config() : disable_admin(true), disable_subprocess_spawn(true), fake_parent_process(true),
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
}
