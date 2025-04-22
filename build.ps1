$HelpMessage = @"
build.ps1 - script to build PetalAPI

Usage:
.\build.ps1 [options]
Options:
-h, --help      Show this help message and exit.
-t, --target    Specify the target to build. Valid options:
                      build_all, build_only_crt, build_only_d3d,
                      build_only_dlls, build_only_drivers, build_only_kernel
                      (Default: build_all)
"@
$Arguments = $args
$ShowHelp = $false
$build = @(
    "build\scripts\i386-build_all.ps1"
    "build\scripts\i386-build_only_crt.ps1"
    "build\scripts\i386-build_only_d3d.ps1"
    "build\scripts\i386-build_only_dlls.ps1"
    "build\scripts\i386-build_only_drivers.ps1"
    "build\scripts\i386-build_only_kernel.ps1"
    "build\tools\sfxcab.exe"
)
$InformationPreference = "Continue"

foreach ($filePath in $build) {
    switch ($filePath) {
        "build\tools\sfxcab.exe" {
            if (-not (Test-Path -Path $filePath -PathType Leaf)) {
                Write-Error "sfxcab.exe is missing!" -Category DeviceError -TargetObject "build\tools\sfxcab.exe" -CategoryReason "MissingFileException"
                exit 1
            }
        }
        default {
            if (-not (Test-Path -Path $filePath -PathType Leaf)) {
                Write-Warning "$filePath is missing!"
            }
        }
    }
}

if ($Arguments -contains "-h" -or $Arguments -contains "--help") {
    $ShowHelp = $true
}

if ($ShowHelp) {
    Write-Host $HelpMessage
    exit 0
}

Write-Information "No arguments provided."
Write-Information "Use -h or --help to see available options."