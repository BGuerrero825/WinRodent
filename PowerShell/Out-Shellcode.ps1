﻿Param (
    [Parameter(Position = 0, Mandatory = $True)]
    [String]
    $InputExe,

    [Parameter(Position = 1, Mandatory = $True)]
    [ValidateScript({ Test-Path $_ })]
    [String]
    $ScriptDir,

    [Parameter(Position = 2, Mandatory = $True)]
    [ValidateScript({ Test-Path $_ })]
    [String]
    $InputMapFile,

    [Parameter(Position = 3, Mandatory = $True)]
    [String]
    $ShellcodeOutputFile
)
Write-Host "   Script Dir:       $ScriptDir"
Write-Host "   Input Exe:        $InputExe"
Write-Host "   Input Map:        $InputMapFile"
Write-Host "   Output File:      $ShellcodeOutputFile"

# Make sure output path exists
$OutPath = Split-Path -Path $ShellcodeOutputFile

if ( -not ( Test-Path -Path $OutPath ) )
{
    Write-Output "      Creating output path"
    New-Item -Path $OutPath -ItemType Directory > $null
}

$GetPEHeader = Join-Path $ScriptDir Get-PEHeader.ps1

. $GetPEHeader

$PE = Get-PEHeader $InputExe -GetSectionData
$TextSection = $PE.SectionHeaders | Where-Object { $_.Name -eq '.text' }

$MapContents = Get-Content $InputMapFile

#$TextSectionInfo = @($MapContents | Where-Object { $_ -match '\.text\W+CODE' })[0]
$TextSectionInfo = @($MapContents | Where-Object { $_ -match 'CODE' })[0]
# Possible fix for VS 2017, sufficient to match on just CODE in line.
$ShellcodeLength = [Int] "0x$(( $TextSectionInfo -split ' ' | Where-Object { $_ } )[1].TrimEnd('H'))" - 1

Write-Host "   Shellcode length: 0x$(($ShellcodeLength + 1).ToString('X4'))"

[IO.File]::WriteAllBytes($ShellcodeOutputFile, $TextSection.RawData[0..$ShellcodeLength])
