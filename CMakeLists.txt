cmake_minimum_required(VERSION 3.17)
set(CMAKE_TOOLCHAIN_FILE ${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake
        CACHE STRING "Vcpkg toolchain file")

project(sandboxtank)
find_package(nlohmann_json CONFIG REQUIRED)

set(CMAKE_CXX_STANDARD 20)
add_definitions(-DUNICODE -D_UNICODE)
file(GLOB MMF_SRC
        "cpp-mmf/*.hpp"
        "cpp-mmf/*.cpp"
        )
file(GLOB_RECURSE SRC
        "src/*.h"
        "src/*.hpp"
        "src/*.cpp"
        )
add_executable(sandboxtank ${SRC} ${MMF_SRC})
target_link_libraries(sandboxtank PRIVATE nlohmann_json nlohmann_json::nlohmann_json)