#pragma once

#include <filesystem>
#include <mutex>
#include <string>

#include <Shlobj.h>

#include "../windows_include.hpp"
#include "../../cpp-mmf/memory_mapped_file.hpp"
#include "../utils/StringUtils.h"
#include "../utils/sys/safer/HandleSafe.hpp"
#include "../utils/InterProcessMutex.hpp"

using ::maxisoft::utils::ws2s;

namespace maxisoft::sandbox
{
    template<class Data>
    class SharedMemory
    {
    public:
        using path = std::filesystem::path;

        static constexpr const wchar_t *const extension = L".sbxdat";
        static constexpr const wchar_t *const default_directory = L".mappsandbox";
    public:

        explicit SharedMemory(const std::wstring &id) : SharedMemory(id, default_directory)
        {
        }

        SharedMemory(const std::wstring &id, const std::wstring &subdir) : id_(id), mtx_(id)
        {
            path_ = subdir.empty() ? public_folder() / (id_ + extension) : public_folder() / subdir / (id_ + extension);
            if (!subdir.empty())
            {
                const auto parent_path = path_.parent_path();
                if (!is_directory(parent_path))
                {
                    create_directory(parent_path);
                }
                if (is_directory(parent_path))
                {
                    cleanup_dir(parent_path);
                }
            }
            const bool need_init = !exists(path_);
            std::unique_lock<decltype(mtx_)> lock(mtx_);
            memory_mapped_file_.open(path_.c_str(), memory_mapped_file::if_exists_just_open,
                                     memory_mapped_file::if_doesnt_exist_create);
            memory_mapped_file_.map(0, sizeof(Data) + 1);
            assert(memory_mapped_file_.is_open());
            assert(memory_mapped_file_.mapped_size() >= sizeof(Data));
            if (need_init)
            {
                std::error_code err{};
                permissions(path_, std::filesystem::perms::group_all | std::filesystem::perms::others_all,
                            std::filesystem::perm_options::replace, err);
                initialize_data_content(data());
            }
        }

        bool flush()
        {
            return memory_mapped_file_.flush();
        }

        std::unique_lock<maxisoft::InterProcessMutex> get_lock()
        {
            return std::move(std::unique_lock<decltype(mtx_)>(mtx_));
        }

        ~SharedMemory()
        {
            remove();
        }

        Data *data()
        {
            return reinterpret_cast<Data *>(memory_mapped_file_.data());
        }

        void remove()
        {
            if (memory_mapped_file_.is_open())
            {
                memory_mapped_file_.close();
            }
            if (mtx_.valid())
            {
                std::unique_lock<decltype(mtx_)> lock(mtx_);
                if (!path_.empty() && exists(path_))
                {
                    std::error_code err{};
                    std::filesystem::remove(path_, err);
                    if (err)
                    {
                        auto msg = std::string("unable to remove file: ") + path_.string() + " error code: " + std::to_string(err.value());
                        throw std::exception(msg.c_str());
                    }
                }
            }
        }

    private:

        static size_t cleanup_dir(const path &base_dir)
        {
            return cleanup_dir(base_dir, std::chrono::hours(24 * 5));
        }

        template<class Rep, class Period>
        static size_t cleanup_dir(const path &base_dir, std::chrono::duration<Rep, Period> howold)
        {
            using namespace std::filesystem;

            const auto now = file_time_type::clock::now();
            size_t count = 0;
            for (const auto &sub : directory_iterator(base_dir))
            {
                try
                {
                    if (is_regular_file(sub) && sub.path().extension() == extension)
                    {
                        file_time_type t = last_write_time(sub);
                        if (now - t > howold)
                        {
                            std::filesystem::remove(sub);
                            count++;
                        }
                    }
                }
                catch (std::error_code &)
                {
                    //ignore
                }
            }
            return count;
        }

        static path public_folder()
        {
            struct _locals
            {
                PWSTR folder;

                explicit _locals() = default;

                ~_locals()
                {
                    if (folder != nullptr)
                    {
                        CoTaskMemFree(folder);
                    }
                }
            } locals{};

            if (::SHGetKnownFolderPath(FOLDERID_Public, KF_FLAG_NO_ALIAS | KF_FLAG_DEFAULT_PATH, nullptr,
                                       &locals.folder) == S_OK)
            {
                return path(locals.folder);
            }
            throw std::exception("unable to get public folder path");
        }

        template<class T = Data>
        static void initialize_data_content(T *ptr, std::enable_if_t<
                std::is_default_constructible_v<T> &&
                std::is_move_assignable_v<T>> * = nullptr)
        {
            assert(ptr != nullptr);
            *ptr = std::move(T{});
        }

        template<class T = Data>
        static void initialize_data_content(T *ptr, std::enable_if_t<
                std::is_default_constructible_v<T> &&
                std::is_copy_assignable_v<T> && !std::
                is_move_assignable_v<T>> * = nullptr)
        {
            assert(ptr != nullptr);
            *ptr = T{};
        }

        template<class T = Data>
        static void initialize_data_content(T *ptr, std::enable_if_t<
                !std::is_default_constructible_v<T> ||
                !(std::is_move_assignable_v<T> || std::
                is_move_assignable_v<T>)> * = nullptr)
        {
            assert(ptr != nullptr);
            SecureZeroMemory(ptr, sizeof(T));
        }


    private:
        std::wstring id_;
        maxisoft::InterProcessMutex mtx_;
        memory_mapped_file::writable_mmf memory_mapped_file_;
        path path_;
    };
}



