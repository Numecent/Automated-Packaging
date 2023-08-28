########################################################################
#  Auto_Install_from_json.ps1
#  Date: 2022-01-09
#  Author: Thomas Coulson
#
#  Description:
#  This script will auto run a json in NIP_software\auto
#
#  Updated: 2023-08-09
#	Added back missing check to handle multiple valid install files in Auto folder
########################################################################


$runningPS = Get-WmiObject Win32_Process -Filter "Name='powershell.exe' AND CommandLine LIKE 'Auto_Install_from_json.ps1%'"


#Set localmachine dir
$folder = 'C:\NIP_software'

function Test-FileLock {
  param ([parameter(Mandatory = $true)][string]$Path)

  $oFile = New-Object System.IO.FileInfo $Path

  if ((Test-Path -Path $Path) -eq $false) {
    return $false
  }

  try {
    $oStream = $oFile.Open([System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
    if ($oStream) {
      $oStream.Close()
    }
    $false
  }
  catch {
    # file is locked by a process.
    return $true
  }
}

If ($runningps.Count -gt 1) { exit }

#Wait for file
do {
  $filecheck = Test-Path "$folder\auto\*" -Include '*json'

}until ($filecheck -eq $True)

$installjson = Get-ChildItem $folder\auto | Where-Object { $_.Name -Like '*.json' }

if ($installjson.count -gt 1) {
  foreach ($a in $installjson) {
    $JsonValidityCheck = ((get-content $a.FullName) | ConvertFrom-Json ).VirtualizationSettings.DefaultDispositionLayer
    if ($null -ne $JsonValidityCheck) {
      $installjsonName = $a | Select-Object -ExpandProperty Name
    }

  }

}
else {
  $installjsonName = Get-ChildItem $folder\auto | Where-Object { $_.Name -Like '*.json' } | Select-Object -ExpandProperty Name
}


if ($installjsonName -notlike "*sccmauto.json") {

  do {
    $filecheck = Test-Path "$folder\auto\*" -Include '*msi', '*.exe', '*.ps1', '*.bat', '*.cmd'

  }until ($filecheck -eq $True)

  $installfiles = Get-ChildItem $folder\auto | Where-Object { $_.Name -Like ($installjson.basename + "*.msi") -or $_.Name -Like ($installjson.basename + "*.exe") -or $_.Name -Like ($installjson.basename + "*.ps1") -or $_.Name -Like ($installjson.basename + "*.bat") -or $_.Name -Like ($installjson.basename + "*.cmd") } | Select-Object -ExpandProperty Name

  foreach ($Installfile in $Installfiles) {
    do {
      $filecheck = Test-FileLock $installfile
      if ($filecheck -eq $True) { sleep 5 }
    }until ($filecheck -eq $False)
  }
}

#Run studio prep
powershell.exe -ep bypass -file $folder\scripts\CloudpagingStudio-prep.ps1 $true

#Run studio nip
powershell.exe -ep bypass "& `"$folder\scripts\studio-nip.ps1`" -config_file_path `'$folder\auto\$installjsonName`'"
