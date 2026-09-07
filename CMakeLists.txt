cmake_minimum_required(VERSION 3.15)
project(CodeBreak VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(CB_BUILD_CLI "Build the command line tool" ON)
option(CB_BUILD_GUI "Build the Windows GUI application" ON)

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

if(CB_BUILD_CLI)
    add_executable(codebreak-cli src/cli/main_cli.cpp)
    target_link_libraries(codebreak-cli PRIVATE cb_core)
    if(MSVC)
        target_compile_options(codebreak-cli PRIVATE /W4 /utf-8 /permissive-)
    endif()
endif()

if(CB_BUILD_GUI)
    if(NOT WIN32)
        message(FATAL_ERROR "The GUI target requires Windows (MSVC or MinGW).")
    endif()

    add_executable(CodeBreak WIN32
        src/host/main.cpp
        src/host/app.rc
    )
    target_link_libraries(CodeBreak PRIVATE cb_core)
    target_include_directories(CodeBreak PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/host)
    if(MSVC)
        target_compile_options(CodeBreak PRIVATE /W4 /utf-8 /permissive- /wd4150)
        target_link_options(CodeBreak PRIVATE /SUBSYSTEM:WINDOWS /MANIFEST:NO)
    else()
        enable_language(RC)
        target_compile_options(CodeBreak PRIVATE -Wall -Wextra -Wno-unused-parameter -Wno-unknown-pragmas)
        target_link_options(CodeBreak PRIVATE -municode -mwindows)
    endif()
    target_link_libraries(CodeBreak PRIVATE comctl32 user32 gdi32 shell32 ole32 oleaut32 comdlg32 dwmapi advapi32 shlwapi)
    install(TARGETS CodeBreak BUNDLE DESTINATION . RUNTIME DESTINATION .)
endif()
