cmake_minimum_required(VERSION 3.20)
project(CVEHarvest LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(CVEHarvest
    src/main.cpp
    src/framework.cpp
    src/evasion.cpp
    src/scanner.cpp
    src/payload_factory.cpp
    src/c2_client.cpp
    src/exploit_modules.cpp
)

target_include_directories(CVEHarvest
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(CVEHarvest
    PRIVATE
        ws2_32
        advapi32
        shell32
        wininet
        crypt32
        shlwapi
        userenv
)

if (MSVC)
    target_compile_options(CVEHarvest PRIVATE /W4 /EHsc /permissive-)
endif()
