@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
if errorlevel 1 (
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
)
if not exist obj mkdir obj

echo Compiling NightShift v1.1...
cl.exe /W4 /O2 /I include /c src\utils.c /Fo:obj\utils.obj
cl.exe /W4 /O2 /I include /c src\help.c /Fo:obj\help.obj
cl.exe /W4 /O2 /I include /c src\alias_manager.c /Fo:obj\alias_manager.obj
cl.exe /W4 /O2 /I include /c src\gp_session.c /Fo:obj\gp_session.obj
cl.exe /W4 /O2 /I include /c src\sql_executor.c /Fo:obj\sql_executor.obj
cl.exe /W4 /O2 /I include /c src\batch_processor.c /Fo:obj\batch_processor.obj
cl.exe /W4 /O2 /I include /c src\dll_loader.c /Fo:obj\dll_loader.obj
cl.exe /W4 /O2 /I include /c src\internal_cmds.c /Fo:obj\internal_cmds.obj
cl.exe /W4 /O2 /I include /c src\command_processor.c /Fo:obj\command_processor.obj
cl.exe /W4 /O2 /I include /c src\main.c /Fo:obj\main.obj

echo Linking...
link.exe /OUT:nightshift.exe obj\utils.obj obj\help.obj obj\alias_manager.obj obj\gp_session.obj obj\sql_executor.obj obj\batch_processor.obj obj\dll_loader.obj obj\internal_cmds.obj obj\command_processor.obj obj\main.obj odbc32.lib ole32.lib uuid.lib

if %ERRORLEVEL% == 0 (
    echo.
    echo Build successful: nightshift.exe
) else (
    echo.
    echo Build FAILED.
)
