param(
    [string]$Configuration = "Release",
    [string]$OutputDir = "",
    [string]$OutputName = "pktmon_backend.dll"
)

$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
if (-not $OutputDir) {
    $OutputDir = Join-Path $Root "build"
}
$BuildDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDir)
$Source = Join-Path $Root "native\src\pktmon_backend.cpp"
$Output = Join-Path $BuildDir $OutputName

New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

function Find-Cl {
    if ($env:CL_EXE -and (Test-Path $env:CL_EXE)) {
        return $env:CL_EXE
    }

    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $installPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($installPath) {
            $candidate = Get-ChildItem -Path (Join-Path $installPath "VC\Tools\MSVC") -Directory |
                Sort-Object Name -Descending |
                Select-Object -First 1
            if ($candidate) {
                $cl = Join-Path $candidate.FullName "bin\Hostx64\x64\cl.exe"
                if (Test-Path $cl) {
                    return $cl
                }
            }
        }
    }

    $candidates = @(
        "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\*\bin\Hostx64\x64\cl.exe",
        "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\*\bin\Hostx64\x64\cl.exe",
        "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\*\bin\Hostx64\x64\cl.exe"
    )
    foreach ($pattern in $candidates) {
        $match = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending |
            Select-Object -First 1
        if ($match) {
            return $match.FullName
        }
    }
    return $null
}

$Cl = Find-Cl
if (-not $Cl) {
    throw "MSVC cl.exe was not found. Install Visual Studio Build Tools or set CL_EXE."
}

$ClDir = Split-Path $Cl -Parent
$VcTools = Split-Path (Split-Path (Split-Path (Split-Path $Cl -Parent) -Parent) -Parent) -Parent
$MsvcInclude = Join-Path $VcTools "include"
$MsvcLib = Join-Path $VcTools "lib\x64"
$WinKitsRoot = "C:\Program Files (x86)\Windows Kits\10"
$WinKitIncludeBase = Join-Path $WinKitsRoot "Include"
$WinKitLibBase = Join-Path $WinKitsRoot "Lib"
$WinKitVersion = Get-ChildItem -Directory $WinKitIncludeBase |
    Sort-Object Name -Descending |
    Select-Object -First 1 -ExpandProperty Name

$IncludePaths = @(
    $MsvcInclude,
    (Join-Path $WinKitIncludeBase "$WinKitVersion\ucrt"),
    (Join-Path $WinKitIncludeBase "$WinKitVersion\um"),
    (Join-Path $WinKitIncludeBase "$WinKitVersion\shared")
)

$LibPaths = @(
    $MsvcLib,
    (Join-Path $WinKitLibBase "$WinKitVersion\ucrt\x64"),
    (Join-Path $WinKitLibBase "$WinKitVersion\um\x64")
)

$env:INCLUDE = ($IncludePaths -join ";")
$env:LIB = ($LibPaths -join ";")
$env:PATH = "$ClDir;$env:PATH"

& $Cl /nologo /std:c++17 /EHsc /LD /O2 /Fe:$Output $Source /link /nologo
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host "Built $Output"
