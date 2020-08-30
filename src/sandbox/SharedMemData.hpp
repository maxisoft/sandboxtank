#pragma once

#include "ProcessContext.hpp"
#include "ProgramArgs.hpp"
#include "Globals.hpp"
#include <array>
#include <optional>
#include "../windows_include.hpp"

namespace maxisoft::sandbox
{
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

        ProcessContext &get_current_context();

        std::optional<std::reference_wrapper<ProcessContext>> get_context(DWORD pid);

        explicit SharedMemData() : magic(s_magic_array),
                                   config(), config_key(), config_length(), time(),
                                   main_process(0),
                                   build_date_hash(s_build_date_hash), contexts(),
                                   error()
        {
        }

        [[nodiscard]] bool valid() const;

    private:
        static constexpr uint64_t s_build_date_hash = maxisoft::hash::hash64(__TIMESTAMP__);
        static constexpr MagicArray s_magic_array = {'S', 'A', 'N', 'D', 'B', 'O', 'X', 'T', 'A', 'N', 'K', '1'};
    };
}
