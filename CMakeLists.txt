cmake_minimum_required(VERSION 3.10)

project(coro_socks)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

include(cmake/settings.cmake)

add_subdirectory(third-party/asiomp)

include(FetchContent)

FetchContent_Declare(
  yaml-cpp
  GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
  GIT_TAG 0.8.0
)
FetchContent_GetProperties(yaml-cpp)

if(NOT yaml-cpp_POPULATED)
  message(STATUS "Fetching yaml-cpp...")
  FetchContent_Populate(yaml-cpp)
  add_subdirectory(${yaml-cpp_SOURCE_DIR} ${yaml-cpp_BINARY_DIR})
endif()

file(GLOB_RECURSE srcs ${PROJECT_SOURCE_DIR}/src/*.cpp)
file(GLOB_RECURSE hrds ${PROJECT_SOURCE_DIR}/src/*.h)

include_directories(
    src
)

add_executable(${PROJECT_NAME} main.cpp ${srcs})

target_link_libraries(${PROJECT_NAME} PUBLIC
    asiomp
    yaml-cpp::yaml-cpp
)

#
# Clang-Format
#
find_program(CLANG_FORMAT_EXECUTABLE
    NAME "clang-format"
    PATHS "/usr/bin" "/usr/local/bin"
)

if (CLANG_FORMAT_EXECUTABLE)
    message(STATUS "Successfully find program `clang-format`")
    message(STATUS "You can use the `make clang-format` command to automatically format the code style")
    add_custom_target(clang-format ALL
    COMMAND
        ${CLANG_FORMAT_EXECUTABLE} --style=file -i ${hdrs};${srcs};${PROJECT_SOURCE_DIR}/main.cpp
    COMMENT
        "Automatically format the code style"
    )
endif()

#
# Valgrind
#
find_program(VALGRIND_EXECUTABLE
    NAMES "valgrind"
    PATHS "/usr/bin" "/usr/local/bin"
)

if (VALGRIND_EXECUTABLE)
    message(STATUS "Successfully find program `valgrind`")
    message(STATUS "You can use the `make valgrind` command to perform memory leak detection")
    add_custom_target(valgrind
    COMMAND
        ${VALGRIND_EXECUTABLE} --log-file=memcheck.log --leak-check=full --trace-children=yes --track-origins=yes $<TARGET_FILE:${PROJECT_NAME}>
    COMMENT
        "Perform memory leak detection, end with `Ctrl + C`"
    )
endif()