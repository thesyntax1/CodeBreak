cmake_minimum_required(VERSION 3.15)
project(CodeBreak VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CB_CORE_SOURCES
    src/analyze.cpp
    src/pe.cpp
    src/zipfmt.cpp
    src/axml.cpp
    src/dex.cpp
    src/elf.cpp
    src/otherfmts.cpp
    src/miscfmt.cpp
    src/olefmt.cpp
    src/x509.cpp
    src/report.cpp
    src/util.cpp
    src/hashes.cpp
    src/risk.cpp
    src/jsonr.cpp
)

add_library(cb_core STATIC ${CB_CORE_SOURCES})
target_include_directories(cb_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
if(MSVC)
    target_compile_options(cb_core PRIVATE /W4 /utf-8 /permissive-)
else()
    target_compile_options(cb_core PRIVATE -Wall -Wextra -Wno-unused-parameter)
endif()

add_executable(codebreak-cli src/cli/main_cli.cpp)
target_link_libraries(codebreak-cli PRIVATE cb_core)
if(MSVC)
    target_compile_options(codebreak-cli PRIVATE /W4 /utf-8 /permissive-)
    target_link_options(codebreak-cli PRIVATE /SUBSYSTEM:CONSOLE)
endif()
install(TARGETS codebreak-cli RUNTIME DESTINATION .)
