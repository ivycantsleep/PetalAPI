@echo off

title PetalAPI Builder

cls

:Menu

echo:
echo: PetalAPI Build Script
echo: _______________________________________________________
echo:
echo: [1] Build all
echo: [2] Only build core DLLs
echo: [3] Only build the kernel
echo: [4] Only build drivers
echo: [5] Only build PetalCRT
echo: [6] Only build PetalD3D
echo: _______________________________________________________
echo:
echo: Press the corresponding number key to select an option.

choice /C:123456 /N
set _erl=%errorlevel%

if %_erl%==6 "build/scripts/i386-build_only_d3d.cmd" & goto :Menu
if %_erl%==5 "build/scripts/i386-build_only_crt.cmd" & goto :Menu
if %_erl%==4 "build/scripts/i386-build_only_drivers.cmd" & goto :Menu
if %_erl%==3 "build/scripts/i386-build_only_kernel.cmd" & goto :Menu
if %_erl%==2 "build/scripts/i386-build_only_dlls.cmd" & goto :Menu
if %_erl%==1 "build/scripts/i386-build_all.cmd" & goto :Menu