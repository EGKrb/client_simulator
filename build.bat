@echo off
setlocal

set VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat
set SRC=%~dp0
set CURL_DEV=%SRC%third_party\curl-8.22.0_1-win64-mingw

call "%VCVARS%"
if errorlevel 1 exit /b 1

if not exist "%SRC%libcurl.lib" (
    lib /machine:x64 /def:"%CURL_DEV%\bin\libcurl-x64.def" /out:"%SRC%libcurl.lib"
    if errorlevel 1 exit /b 1
    echo [OK] Import library generated: libcurl.lib
)

if not exist "%SRC%obj" mkdir "%SRC%obj"

echo === Building example_usage.exe ===
cl /nologo /std:c++17 /EHsc /O2 /W3 ^
    /I"%CURL_DEV%\include" ^
    /Fo"%SRC%obj\\" ^
    "%SRC%client_simulator.cpp" ^
    "%SRC%example_usage.cpp" ^
    /Fe:"%SRC%example_usage.exe" ^
    /link "%SRC%libcurl.lib"
if errorlevel 1 exit /b 1

echo === Building smoke_test.exe ===
cl /nologo /std:c++17 /EHsc /O2 /W3 ^
    /I"%CURL_DEV%\include" ^
    /Fo"%SRC%obj\\" ^
    "%SRC%client_simulator.cpp" ^
    "%SRC%smoke_test.cpp" ^
    /Fe:"%SRC%smoke_test.exe" ^
    /link "%SRC%libcurl.lib"
if errorlevel 1 exit /b 1

copy /Y "%CURL_DEV%\bin\libcurl-x64.dll" "%SRC%libcurl-x64.dll" >nul
copy /Y "%CURL_DEV%\bin\curl-ca-bundle.crt" "%SRC%curl-ca-bundle.crt" >nul

echo === Build complete ===
echo   example_usage.exe   - full purchase flow demo (hits shop.example.com)
echo   smoke_test.exe      - end-to-end validation via httpbin.org echo endpoint

echo [OK] Build complete: client_simulator.exe