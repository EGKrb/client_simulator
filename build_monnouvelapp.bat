@echo off
setlocal

rem ==========================================================================
rem  Build MonNouvelApp.exe en liant la bibliotheque statique client_simulator
rem  1) genere client_simulator.lib (libcurl import + client_simulator.obj)
rem  2) compile src\monnouvelapp.cpp -> bin\MonNouvelApp.exe
rem     + passerelle ltg integree (pki/rules/mock/gateway, mode --gateway)
rem     + moteur NightShift (mode --ns/--ns-batch/--ns-repl)
rem     + CLI ghidra-rpc (mode --ghidra, package Python vendorise dans
rem       C:\client_simulator\ghidra-rpc + venv dedie)
rem ==========================================================================

set VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat
set SRC=C:\client_simulator
set APP=%SRC%\bin
set CURL_DEV=%SRC%\third_party\curl-8.22.0_1-win64-mingw

call "%VCVARS%"
if errorlevel 1 exit /b 1

rem --- 1. Import library libcurl.lib (si absente) ---------------------------
if not exist "%SRC%\libcurl.lib" (
    lib /machine:x64 /def:"%CURL_DEV%\bin\libcurl-x64.def" /out:"%SRC%\libcurl.lib"
    if errorlevel 1 exit /b 1
)

rem --- 2. Objet de la bibliotheque statique --------------------------------
if not exist "%SRC%\obj" mkdir "%SRC%\obj"

cl /nologo /std:c++17 /EHsc /O2 /W3 /MD ^
    /I"%CURL_DEV%\include" ^
    /Fo"%SRC%\obj\\" ^
    /c "%SRC%\client_simulator.cpp"
if errorlevel 1 exit /b 1

rem --- 3. Bibliotheque statique client_simulator.lib -----------------------
lib /machine:x64 /out:"%SRC%\client_simulator.lib" "%SRC%\obj\client_simulator.obj"
if errorlevel 1 exit /b 1
echo [OK] client_simulator.lib genere

rem --- 3b. Passerelle ltg integree (sources localgate) ------------------------
rem Compile pki/rules/mock_controller/gateway (+ http1 header-only) et lie la
rem VM Luau + OpenSSL(vcpkg). Active MonNouvelApp.exe --gateway [port].
set LUAU=%SRC%\build\_deps\luau-src
set LUAU_LIB=%SRC%\build\_deps\luau-build\Release
set VCPKG=%SRC%\vcpkg_installed\x64-windows
set LTG_OBJ_DIR=%SRC%\obj\ltg
if not exist "%LTG_OBJ_DIR%" mkdir "%LTG_OBJ_DIR%"

rem       NB: %VCPKG%\include doit passer AVANT %CURL_DEV%\include : le bundle
rem       MinGW embarque d'anciens headers OpenSSL qui casseraient pki/gateway.
cl /nologo /std:c++17 /EHsc /O2 /W3 /MD ^
    /I"%VCPKG%\include" ^
    /I"%CURL_DEV%\include" ^
    /I"%LUAU%\Compiler\include" ^
    /I"%LUAU%\Ast\include" ^
    /I"%LUAU%\Common\include" ^
    /I"%LUAU%\VM\include" ^
    /I"%LUAU%\Config\include" ^
    /I"%SRC%" ^
    /Fo"%LTG_OBJ_DIR%\\" ^
    /c "%SRC%\pki.cpp" "%SRC%\rules.cpp" "%SRC%\mock_controller.cpp" "%SRC%\gateway.cpp" "%SRC%\mockgen.cpp"
if errorlevel 1 exit /b 1
echo [OK] pki/rules/mock/gateway objets generes (%LTG_OBJ_DIR%)

rem --- 3c. Moteur NightShift (nuit C) ----------------------------------------
rem Compile les unites C du module C:\client_simulator\nightshift (sauf main.c)
rem + le pont src\nightshift_bridge.c, lies dans l'exe pour --ns/--ns-batch/--ns-repl.
set NS=%SRC%\nightshift
set NS_OBJ_DIR=%SRC%\obj\ns
if not exist "%NS_OBJ_DIR%" mkdir "%NS_OBJ_DIR%"

cl /nologo /O2 /W3 /MD ^
    /I"%NS%\include" ^
    /Fo"%NS_OBJ_DIR%\\" ^
    /c ^
    "%NS%\src\alias_manager.c" ^
    "%NS%\src\batch_processor.c" ^
    "%NS%\src\command_processor.c" ^
    "%NS%\src\dll_loader.c" ^
    "%NS%\src\gp_session.c" ^
    "%NS%\src\help.c" ^
    "%NS%\src\internal_cmds.c" ^
    "%NS%\src\sql_executor.c" ^
    "%NS%\src\utils.c" ^
    "%SRC%\src\nightshift_bridge.c"
if errorlevel 1 exit /b 1
echo [OK] moteur NightShift compile (%NS_OBJ_DIR%)

rem --- 3d. CLI ghidra-rpc (package Python) -----------------------------------
rem Vendorise dans C:\client_simulator\ghidra-rpc et installe dans un venv
rem dedie. Le mode --ghidra de MonNouvelApp.exe lance ce venv en sous-processus.
set GRPC=%SRC%\ghidra-rpc
set GRPC_VENV=%GRPC%\.venv

if not exist "%GRPC%\pyproject.toml" (
    echo [ERREUR] Package ghidra-rpc absent de %GRPC%.
    echo Decompressez ghidra-rpc-main.zip dans C:\client_simulator\ghidra-rpc
    exit /b 1
)

if not exist "%GRPC_VENV%\Scripts\python.exe" (
    echo [..] Creation du venv ghidra-rpc + installation du package ^(une fois^)...
    python -m venv "%GRPC_VENV%"
    if errorlevel 1 exit /b 1
    "%GRPC_VENV%\Scripts\python.exe" -m pip install --upgrade pip >nul 2>&1
    "%GRPC_VENV%\Scripts\python.exe" -m pip install "%GRPC%"
    if errorlevel 1 exit /b 1
)
echo [OK] CLI ghidra-rpc pret : "%GRPC_VENV%\Scripts\python.exe" -m ghidra_rpc.cli

if not defined GHIDRA_INSTALL_DIR (
    if exist "C:\Users\%USERNAME%\ghidra\ghidra_12.1.3_PUBLIC\ghidraRun.bat" (
        set GHIDRA_INSTALL_DIR=C:\Users\%USERNAME%\ghidra\ghidra_12.1.3_PUBLIC
    )
)
if defined GHIDRA_INSTALL_DIR (
    echo [OK] GHIDRA_INSTALL_DIR = %GHIDRA_INSTALL_DIR%
) else (
    echo [AVERTISSEMENT] GHIDRA_INSTALL_DIR non defini : le mode --ghidra ne
    echo                  pourra pas demarrer de daemon sans le poser.
)

rem --- 3e. Pont C++ ghidra-rpc ------------------------------------------------
rem Compile src\ghidra_bridge.cpp -> obj\app\ghidra_bridge.obj (mode --ghidra).
if not exist "%SRC%\obj\app" mkdir "%SRC%\obj\app"
cl /nologo /std:c++17 /EHsc /O2 /W3 /MD ^
    /I"%SRC%" ^
    /Fo"%SRC%\obj\app\\" ^
    /c "%SRC%\src\ghidra_bridge.cpp"
if errorlevel 1 exit /b 1
echo [OK] pont ghidra-rpc compile (obj\app\ghidra_bridge.obj)

rem --- 4. Compilation de MonNouvelApp.exe -----------------------------------
if not exist "%SRC%\obj\app" mkdir "%SRC%\obj\app"

cl /nologo /std:c++17 /EHsc /O2 /W3 /MD ^
    /I"%VCPKG%\include" ^
    /I"%CURL_DEV%\include" ^
    /I"%LUAU%\Compiler\include" ^
    /I"%LUAU%\Ast\include" ^
    /I"%LUAU%\Common\include" ^
    /I"%LUAU%\VM\include" ^
    /I"%LUAU%\Config\include" ^
    /I"%SRC%" ^
    /I"%NS%\include" ^
    /Fo"%SRC%\obj\app\\" ^
    "%SRC%\src\monnouvelapp.cpp" ^
    "%LTG_OBJ_DIR%\pki.obj" ^
    "%LTG_OBJ_DIR%\rules.obj" ^
    "%LTG_OBJ_DIR%\mock_controller.obj" ^
    "%LTG_OBJ_DIR%\gateway.obj" ^
    "%LTG_OBJ_DIR%\mockgen.obj" ^
    "%NS_OBJ_DIR%\alias_manager.obj" ^
    "%NS_OBJ_DIR%\batch_processor.obj" ^
    "%NS_OBJ_DIR%\command_processor.obj" ^
    "%NS_OBJ_DIR%\dll_loader.obj" ^
    "%NS_OBJ_DIR%\gp_session.obj" ^
    "%NS_OBJ_DIR%\help.obj" ^
    "%NS_OBJ_DIR%\internal_cmds.obj" ^
    "%NS_OBJ_DIR%\sql_executor.obj" ^
    "%NS_OBJ_DIR%\utils.obj" ^
    "%NS_OBJ_DIR%\nightshift_bridge.obj" ^
    "%SRC%\obj\app\ghidra_bridge.obj" ^
    /Fe:"%APP%\MonNouvelApp.exe" ^
    /link "%SRC%\client_simulator.lib" "%SRC%\libcurl.lib" ^
    "%LUAU_LIB%\Luau.VM.lib" "%LUAU_LIB%\Luau.Compiler.lib" ^
    "%LUAU_LIB%\Luau.Ast.lib" "%LUAU_LIB%\Luau.Config.lib" ^
    "%VCPKG%\lib\libssl.lib" "%VCPKG%\lib\libcrypto.lib" ^
    crypt32.lib ws2_32.lib odbc32.lib ole32.lib uuid.lib
if errorlevel 1 exit /b 1

rem --- 5. DLL + certificats requis a cote de l'exe ---------------------------
copy /Y "%CURL_DEV%\bin\libcurl-x64.dll" "%APP%\libcurl-x64.dll" >nul
copy /Y "%CURL_DEV%\bin\curl-ca-bundle.crt" "%APP%\curl-ca-bundle.crt" >nul
copy /Y "%VCPKG%\bin\libssl-3-x64.dll" "%APP%\libssl-3-x64.dll" >nul
copy /Y "%VCPKG%\bin\libcrypto-3-x64.dll" "%APP%\libcrypto-3-x64.dll" >nul

echo.
echo === Build complete ===
echo   %APP%\MonNouvelApp.exe
echo   Modes client_simulator :
echo     MonNouvelApp.exe --sim-get ^<url^>
echo     MonNouvelApp.exe --sim-post ^<url^> ^<json^>
echo     MonNouvelApp.exe --sim-put  ^<url^> ^<json^>
echo     MonNouvelApp.exe --sim-del  ^<url^>
echo     MonNouvelApp.exe --sim-purchase ^<baseUrl^>
echo   Passerelle de test HTTPS (comme ltg.exe) :
echo     MonNouvelApp.exe --gateway [port]   ^(defaut 7080^)
echo   Trace de demarrage :
echo     MonNouvelApp.exe --trace ^<exe^> [args...] --trace-timeout 10
echo     MonNouvelApp.exe --trace-attach ^<pid^> --trace-timeout 60   ^(surveille un processus deja lance, ex. session Target^)
echo   Moteur NightShift integre :
echo     MonNouvelApp.exe --ns "version; load kernel32; peinfo; unload"
echo     MonNouvelApp.exe --ns "mapload kernel32; sections; symbols GetSystemT"
echo     MonNouvelApp.exe --ns-batch fichier.bat   ^(CMD:/SQL:/LOGIN:/WAIT:^)
echo     MonNouvelApp.exe --ns-repl                ^(REPL sur stdin^)
echo   CLI ghidra-rpc integre ^(decompile, xrefs, search, patch, ...^) :
echo     MonNouvelApp.exe --ghidra list-instances
echo     MonNouvelApp.exe --ghidra start --project C:\ROBUX.gpr [--headless]
echo     MonNouvelApp.exe --ghidra load --project C:\ROBUX.gpr ^<binaire^>
echo     MonNouvelApp.exe --ghidra decompile --project C:\ROBUX.gpr ^<bin^> ^<func^>
echo     MonNouvelApp.exe --ghidra help                  ^(aide complete^)