@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b %errorlevel%
cl /nologo /EHsc /std:c++20 /W4 /WX probe.cpp /Fe:probe.exe
if errorlevel 1 exit /b %errorlevel%
probe.exe
