cmake_minimum_required(VERSION 3.15)
project(CodeBreak VERSION 1.0.0 LANGUAGES CXX)

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
    src/util.cpp
    src/hashes.cpp
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
    target_include_directories(CodeBreak PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/webview2/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/host
    )
    if(MSVC)
        target_compile_options(CodeBreak PRIVATE /W4 /utf-8 /permissive- /wd4150)
        target_link_options(CodeBreak PRIVATE /SUBSYSTEM:WINDOWS)
    else()
        enable_language(RC)
        target_compile_options(CodeBreak PRIVATE -Wall -Wextra -Wno-unused-parameter -Wno-unknown-pragmas)
        target_link_options(CodeBreak PRIVATE -municode -mwindows)
    endif()
    target_link_libraries(CodeBreak PRIVATE user32 gdi32 shell32 ole32 oleaut32 comdlg32 dwmapi advapi32 shlwapi)

    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(WV2_ARCH_DIR win-x64)
    else()
        set(WV2_ARCH_DIR win-x86)
    endif()
    set(WV2_LOADER ${CMAKE_CURRENT_SOURCE_DIR}/third_party/webview2/runtimes/${WV2_ARCH_DIR}/WebView2Loader.dll)
    if(EXISTS "${WV2_LOADER}")
        add_custom_command(TARGET CodeBreak POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different "${WV2_LOADER}" "$<TARGET_FILE_DIR:CodeBreak>"
            COMMENT "Copying WebView2Loader.dll"
        )
        install(TARGETS CodeBreak BUNDLE DESTINATION . RUNTIME DESTINATION .)
        install(FILES "${WV2_LOADER}" DESTINATION .)
    else()
        message(WARNING "WebView2Loader.dll for ${WV2_ARCH_DIR} not found at ${WV2_LOADER}")
    endif()
endif()
