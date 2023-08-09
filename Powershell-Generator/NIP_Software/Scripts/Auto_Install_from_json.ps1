########################################################################
#  CreateJson:.ps1
#  Date: 2023-01-09
#  Author: Thomas Coulson
#
#  Description:
#  This script will generate a default no input packaging json for msi's/exes
#  Updated 2023-01-02:
#	Added most variablised options
#  Updated: 2023-02-07
#	Added custom file & Reg dispositions.
#	Added Reg modify and File Add params.
#  Updated: 2023-08-09
#	Added support for ps1, cmd, bat
#	
#
########################################################################

Param(
  [Parameter(Mandatory = $true)][ValidateScript({ $_.Replace("`"", '') -like '*.msi' -or $_.Replace("`"", '') -like '*.exe' -or $_.Replace("`"", '') -like '*.bat' -or $_.Replace("`"", '') -like '*.cmd' -or $_.Replace("`"", '') -like '*.ps1' -and (Test-Path -Path $_.Replace("`"", '') -PathType Leaf) -eq $true })]
  [string]$Filepath,
  [Parameter(Mandatory = $false)]
  [string]$Description,
  [Parameter(Mandatory = $false)]
  [string]$Name,
  [Parameter(Mandatory = $false)]
  [string]$IconFile,    
  [Parameter(Mandatory = $false)]
  [string]$WorkingFolder,
  [Parameter(Mandatory = $false)]
  [string]$Arguments,
  [Parameter(Mandatory = $false)]
  [string]$StudioCommandline,
  [Parameter(Mandatory = $false)]
  [string]$outputfolder,
  [Parameter(Mandatory = $false)]
  [string]$OutputFileNameNoExt,
  [Parameter(Mandatory = $false)][ValidateSet('LZMA', 'NONE')]
  [string]$Compression = 'LZMA',
  [Parameter(Mandatory = $false)][ValidateSet('AES-256-Enhanced', 'AES-256', 'None')]
  [string]$Encryption = 'AES-256-Enhanced',
  [Parameter(Mandatory = $false)][ValidateSet('3', '4')]
  [string]$DefaultDispositionLayer = 3,
  [Parameter(Mandatory = $false)][ValidateRange(1, [int]::MaxValue)]
  [int]$CaptureTimeoutSec = 1,
  [Parameter(Mandatory = $false)]
  [string[]]$CustomCommandlines,
  [Parameter(Mandatory = $false)]
  [string[]]$RegistryExclusions,
  [Parameter(Mandatory = $false)]
  [string[]]$FileExclusions,
  [Parameter(Mandatory = $false)]
  [psobject[]]$Fileaddition,
  [Parameter(Mandatory = $false)]
  [psobject[]]$Registrymodify,
  [Parameter(Mandatory = $false)]
  [psobject[]]$CustomFileDisposition,
  [Parameter(Mandatory = $false)]
  [psobject[]]$CustomRegistryDisposition,
  [Parameter(Mandatory = $false)]
  [string[]]$ProcessesAllowedAccessToLayer4,
  [Parameter(Mandatory = $false)]
  [string[]]$ProcessesDeniedAccessToLayers3and4,
  [Parameter(Mandatory = $false)]
  [string[]]$SandboxRegistryExclusions,
  [Parameter(Mandatory = $false)]
  [string[]]$SandboxFileExclusions,
  [Parameter(Mandatory = $false)]
  [boolean]$CaptureAllProcesses = $false,
  [Parameter(Mandatory = $false)]
  [boolean]$IncludeSystemInstallationProcesses = $true,
  [Parameter(Mandatory = $false)]
  [boolean]$IgnoreChangesUnderInstallerPath = $true,
  [Parameter(Mandatory = $false)]
  [boolean]$ReplaceRegistryShortPaths = $true,
  [Parameter(Mandatory = $false)]
  [boolean]$IncludeChildProccesses = $true,
  [Parameter(Mandatory = $false)]
  [boolean]$Prerequisites = $false,
  [Parameter(Mandatory = $false)]
  [string[]]$PrerequisiteCommands,
  [Parameter(Mandatory = $false)][ValidateSet('None', 'Register', 'Start')]
  [string]$DefaultServiceVirtualizationAction = 'None',
  [Parameter(Mandatory = $false)]
  [boolean]$FinalizeIntoSTP = $true
)

#Set unparamterised variables
$Projworkingfolder_variable = 'C:\NIP_software\auto'

$date = Get-Date

#set installer path
$filepath = $filepath.Replace("`"", '')
$Projinstaller_variable = (Get-ChildItem "$filepath").name
if ($Projinstaller_variable -like '*.msi') {
  $Projinstaller_variable = "msiexec /i `\`"" + ("$Projworkingfolder_variable\$Projinstaller_variable").replace('\', '\\' ) + "`\`""

  if (!$Arguments) {
    $Arguments = '/qn /norestart'
  }
}
elseif ($Projinstaller_variable -like '*.ps1') {
  $Projinstaller_variable = "powershell.exe -executionpolicy bypass -file `\`"" + ("$Projworkingfolder_variable\$Projinstaller_variable").replace('\', '\\' ) + "`\`""
}
elseif ($Projinstaller_variable -like '*.bat' -or $Projinstaller_variable -like '*.cmd') {
  $Projinstaller_variable = "`\`"" + ("$Projworkingfolder_variable\$Projinstaller_variable").replace('\', '\\' ) + "`\`""
}
else {
  $Projinstaller_variable = "`\`"" + ("$Projworkingfolder_variable\$Projinstaller_variable").replace('\', '\\' ) + "`\`""
}

if ($Arguments) {
  $Projinstallercustom_variable = " $Arguments"
  $Projinstallercustom_variable = $Projinstallercustom_variable.replace('\', '\\' ).replace('"', "`\`"" )
}

#set name

if (!$name) {
  $Name = (Get-ChildItem "$filepath").BaseName + ' cloudpaged'
}
$Name = $Name.Replace('.', '-')

#set description
if (!$Description) {
  $Description = "Automated conversion of $Name Created at $date"
}

$Workingfolder = $Workingfolder.replace('\', '\\' )
$IconFile = $IconFile.replace('\', '\\' )

#set commandline
if (!$StudioCommandline) {
  $StudioCommandline = "$env:windir\System32\cmd.exe /c"
}

$StudioCommandline = $StudioCommandline.replace('\', '\\' )

if (!$outputfolder) {
  $outputfolder = 'C:\NIP_software\output'
}
$outputfolder = $outputfolder.replace('\', '\\' )

if (!$Encryption) {
  $Encryption = 'AES-256-Enhanced'
}

if (!$Compression) {
  $Compression = 'LZMA'
}

#Format commandlines for Json
if ($CustomCommandlines) {
  $CustomCommandlinesjson = @'
,

'@
  foreach ($commandline in $CustomCommandlines) {
    $commandline = '"' + $commandline.replace('\', '\\' ).replace('"', '\"') + '",' + "`n"
    $CustomCommandlinesjson += $commandline
  }
  $CustomCommandlinesjson = $CustomCommandlinesjson.Substring(0, $CustomCommandlinesjson.Length - 2)

}

#Format file exclusion paths for Json
if ($FileExclusions) {
  $FileExclusionsjson = @'
,

'@
  foreach ($ExcludedFile in $FileExclusions) {
    $ExcludedFile = '"' + $ExcludedFile.replace('\', '\\' ).replace('"', '\"') + '",' + "`n"
    $FileExclusionsjson += $ExcludedFile
  }
  $FileExclusionsjson = $FileExclusionsjson.Substring(0, $FileExclusionsjson.Length - 2)

}

#Format sandbox file exclusion paths for Json
if ($SandboxFileExclusions) {
  $SandboxFileExclusionsjson = ""

  foreach ($ExcludedFile in $SandboxFileExclusions) {
    $ExcludedFile = '"' + $ExcludedFile.replace('\', '\\' ).replace('"', '\"') + '",' + "`n"
    if ($ExcludedFile -like "* *") {
      $ExcludedFile = $ExcludedFile.replace('\\', '\\\\' )
    }
    $SandboxFileExclusionsjson += $ExcludedFile
  }
  $SandboxFileExclusionsjson = $SandboxFileExclusionsjson.Substring(0, $SandboxFileExclusionsjson.Length - 2)

}

#Format Registry exclusion paths for Json
if ($RegistryExclusions) {
  $RegistryExclusionsjson = @'
,

'@
  foreach ($ExcludedRegistry in $RegistryExclusions) {
    $ExcludedRegistry = '"' + $ExcludedRegistry.replace('\', '\\' ).replace('"', '\"') + '",' + "`n"
    if ($ExcludedRegistry -like "* *") {
      $ExcludedRegistry = $ExcludedRegistry.replace('\\', '\\\\' )
    }
    $RegistryExclusionsjson += $ExcludedRegistry
  }
  $RegistryExclusionsjson = $RegistryExclusionsjson.Substring(0, $RegistryExclusionsjson.Length - 2)

}

#Format sandbox Registry exclusion paths for Json
if ($SandboxRegistryExclusions) {
  $SandboxRegistryExclusionsjson = ""
  foreach ($ExcludedRegistry in $SandboxRegistryExclusions) {
    $ExcludedRegistry = '"' + $ExcludedRegistry.replace('\', '\\' ).replace('"', '\"') + '",' + "`n"
    if ($ExcludedRegistry -like "* *") {
      $ExcludedRegistry = $ExcludedRegistry.replace('\\', '\\\\' )
    }
    $SandboxRegistryExclusionsjson += $ExcludedRegistry
  }
  $SandboxRegistryExclusionsjson = $SandboxRegistryExclusionsjson.Substring(0, $SandboxRegistryExclusionsjson.Length - 2)

}

#Format File additions for Json
if ($Fileaddition) {

  $FileAdditionNumber = 1
  foreach ($File in $Fileaddition) {
    $Fileadditionjson += "`"File$FileAdditionNumber`": {`n"
    $Fileadditionjson += "`"Name`": `"" + $File.FileName.replace('\', '\\' ).replace('"', '\"') + "`",`n"
    $Fileadditionjson += "`"Destination`": `"" + $File.FileDestination.replace('\', '\\' ).replace('"', '\"') + "`",`n"
    $File.FileContent.split("`r`n") | ForEach-Object {
      $contentescaped += "`"" + $_.replace('\', '\\' ).replace('"', '\"') + "`",`n"
    }
    $contentescaped = $contentescaped.Substring(0, $contentescaped.Length - 2)
    $Fileadditionjson += "`"Content`": [`n + $contentescaped  + `n]`n},"

    $FileAdditionNumber ++
  }
  $Fileadditionjson = $Fileadditionjson.Substring(0, $Fileadditionjson.Length - 1)
}


#Format Registry additions for Json

if ($Registrymodify) {

  $RegistrymodifyNumber = 1
  foreach ($Registry in $Registrymodify) {
    $Registrymodifyjson += "`"Key$RegistrymodifyNumber`": {`n"
    $Registrymodifyjson += "`"Location`": `"" + $Registrymodify.Location.replace('\', '\\' ).replace('"', '\"') + "`",`n"
    $Registrymodifyjson += "`"Keys`": [`n"
    foreach ($v in $Registry.values) {
      $Registrymodifyjson += "`"" + $v.replace('\', '\\' ).replace('"', '\"') + "`",`n"
    }
    $Registrymodifyjson = $Registrymodifyjson.Substring(0, $Registrymodifyjson.Length - 2)
    $Registrymodifyjson += "]`n},`n"

    $RegistrymodifyNumber ++
  }
  $Registrymodifyjson = $Registrymodifyjson.Substring(0, $Registrymodifyjson.Length - 2)
}


# Add custom file dispositions
if ($CustomfileDisposition) {
  $FileAdditionNumber = 1

  foreach ($Customfile in $CustomfileDisposition) {
    $CustomfileDispositionjson += "`"File$FileAdditionNumber`": {`n"
    $CustomfileDispositionjson += "`"Path`": `"" + $Customfile.Path.replace('\', '\\' ).replace('"', '\"') + "`",`n"
    $CustomfileDispositionjson += "`"Layer`": `"" + $Customfile.Layer + "`",`n"
    $CustomfileDispositionjson += "`"Recurse`": `"" + $Customfile.Recurse + "`"`n},`n"
    $FileAdditionNumber ++
  }

  $CustomfileDispositionjson = $CustomfileDispositionjson.Substring(0, $CustomfileDispositionjson.Length - 2)

}

#Add custom Reg disposition
if ($CustomRegistryDisposition) {
  $RegistryAdditionNumber = 1

  foreach ($CustomRegistry in $CustomRegistryDisposition) {
    $CustomRegistryDispositionjson += "`"Registry$RegistryAdditionNumber`": {`n"
    $CustomRegistryDispositionjson += "`"Location`": `"" + $CustomRegistry.Location.replace('\', '\\' ).replace('"', '\"') + "`",`n"
    $CustomRegistryDispositionjson += "`"Layer`": `"" + $CustomRegistry.Layer + "`",`n"
    $CustomRegistryDispositionjson += "`"Recurse`": `"" + $CustomRegistry.Recurse + "`"`n},`n"
    $RegistryAdditionNumber ++
  }

  $CustomRegistryDispositionjson = $CustomRegistryDispositionjson.Substring(0, $CustomRegistryDispositionjson.Length - 2)

}

#workout run time
$filesize = (Get-ChildItem $filepath).Length / 1KB

if ($CaptureTimeoutSec -eq 1) {
  $CaptureTimeoutSec = [math]::Round(60 + $filesize / 1000)
}

#Update Json with variables


$jsonfilebody = @"
    {
        "JsonConfigVersion": 1.2,
        "ProjectSettings": {
            "ProjectName": "$Name",
            "ProjectDescription": "$Description",
            "IconFile": "$IconFile",
            "WorkingFolder": "$WorkingFolder",
            "CommandLine": "$StudioCommandline",
            "TargetOS": [
            ]
        },
        "PreCaptureCommands": [
        ],
        "CaptureSettings": {
            "CaptureTimeoutSec": "$CaptureTimeoutSec",
            "CaptureAllProcesses": $CaptureAllProcesses,
            "IncludeSystemInstallationProcesses": $IncludeSystemInstallationProcesses,
            "IgnoreChangesUnderInstallerPath": $IgnoreChangesUnderInstallerPath,
            "ReplaceRegistryShortPaths": $ReplaceRegistryShortPaths,
            "RegistryExclusions": [
                   "HKEY_USERS\\.DEFAULT",
               "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer",
               "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing",
               "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CURRENTVERSION\\APPMODEL\\STAGINGINFO",
               "HKEY_CURRENT_USER\\SOFTWARE\\CLASSES\\LOCAL SETTINGS\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\AppModel",
               "HKEY_CURRENT_USER\\SOFTWARE\\CLASSES\\LOCAL SETTINGS\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\AppContainer",
               "HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer"$RegistryExclusionsjson
                             ],
            "FileExclusions": [
               "%systemdrive%\\NIP_software",
               "%ProgramData%\\Microsoft\\Windows Defender",
               "%ProgramData%\\Microsoft\\Network",
               "%APPDATA%\\Microsoft\\Windows\\Recent\\CustomDestinations",
               "%LOCALAPPDATA%\\Microsoft",
               "%windir%\\System32\\Tasks",
               "%LOCALAPPDATA%\\ConnectedDevicesPlatform",
               "%windir%\\appcompat",
               "%winDir%\\Installer\\*.msi",
               "%winDir%\\Installer\\*.msp",
               "%windir%\\System32\\Sysprep",
               "%programdata%\\chocolatey",
               "%programdata%\\chocolateyHttpCache",
               "%LocalAppData%\\Packages\\Microsoft.DesktopAppInstaller*",
               "%LocalAppData%\\Packages\\Microsoft.Winget.*",
               "%LocalAppData%\\Packages\\MicrosoftWindows.Client.*",
               "%programfiles%\\WindowsApps\\Microsoft.Winget.*",
               "%Windir%\\Microsoft.NET"$FileExclusionsjson
            ],
            "ProcessExclusions": [],
            "ProcessInclusions": {
                "IncludeChildProccesses": $IncludeChildProccesses,
                "Include": []
            }
        },
        "CaptureCommands": {
            "Enabled": true,
            "Prerequisites": {
                "Enabled": $Prerequisites,
                "Commands": [$PrerequisiteCommands]
            },
            "InstallerPrefix": "md C:\\NIP_software\\Auto\\ 2>NUL & echo exit > \"C:\\NIP_software\\Auto\\$Name-placeholderInstallTarget.bat\" & cmd /c ",
            "InstallerPath": "\"C:\\NIP_software\\Auto\\$Name-placeholderInstallTarget.bat\"",
            "InstallerCommands": "",
            "PostInstallActions": {
                "Enabled": true,
                "Commands": [
                    "C:\\Windows\\System32\\cmd.exe /c $Projinstaller_variable$Projinstallercustom_variable",
                    "rem ",
                    "TIMEOUT /T 5 /NOBREAK >NUL",
                    "del \"C:\\NIP_software\\Auto\\$Name-placeholderInstallTarget.bat\" /F /Q"$CustomCommandlinesjson

                ]
            },
            "DebugMode": false
        },
        "ModifyAssets": {
            "AddFiles": {$Fileadditionjson},
            "ModifyKeys": {$Registrymodifyjson}
        },
        "VirtualizationSettings": {
            "DefaultDispositionLayer": $DefaultDispositionLayer,
            "DefaultServiceVirtualizationAction": "$DefaultServiceVirtualizationAction",
            "FileDispositionLayers": {
                $CustomfileDispositionjson
            },
            "RegistryDispositionLayers": {
                $CustomRegistryDispositionjson
            },
            "SandboxFileExclusions": [
                $SandboxFileExclusionsjson
            ],
            "SandboxRegistryExclusions": [
                $SandboxRegistryExclusionsjson
            ]
        },
        "SecurityOverrideSettings": {
            "AllowAccessLayer4": {
                "AllowReadAndCopy": true,
                "Proccesses": [$ProcessesAllowedAccessToLayer4
                ]
            },
            "DenyAccessLayer3": [$ProcessesDeniedAccessToLayers3and4]
        },
        "OutputSettings": {
            "EncryptionMethod": "$Encryption",
            "CompressionMethod": "$Compression",
            "OutputFileNameNoExt": "$OutputFileNameNoExt",
            "FinalizeIntoSTP": $FinalizeIntoSTP,
            "OutputFolder": "$outputfolder"
        }
    }
"@


$jsonoutputlocation = (Get-ChildItem $filepath).DirectoryName + '\' + (Get-ChildItem $filepath).BaseName + '.json'

$jsonfilebody.Replace("False", "false").Replace("True", "true") | Set-Content $jsonoutputlocation
