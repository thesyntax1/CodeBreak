@echo off
setlocal
where cmake >nul 2>nul
if errorlevel 1 (
    echo CMake was not found on PATH. Install the "Desktop development with C++"
    echo workload from Visual Studio or standalone CMake, then re-run.
    exit /b 1
)
cmake -S . -B build -A x64
if errorlevel 1 exit /b 1
cmake --build build --config Release
if errorlevel 1 exit /b 1
echo.
echo Build complete:
echo   build\Release\CodeBreak.exe
echo   build\Release\codebreak-cli.exe
endlocal
