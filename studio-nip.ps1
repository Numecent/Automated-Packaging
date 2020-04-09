#   Cloudpaging Studio - Auto-package
#
#   Copyright (c) 2020 Numecent, Inc.  All rights reserved.
#
#   This file is an unpublished work and the proprietary and confidential
#   information of Numecent.  Should this source code become published,
#   it is entitled to the fullest protection under the copyright laws,
#   as it was created as early as 1996, and continues to be updated and
#   owned by Numecent. Use, disclosure, reproduction, or distribution is
#   prohibited except as permitted by express written license agreement
#   with Numecent Inc.
#
# Revision March 13, 2020

<#
.SYNOPSIS
    Numecent Studio - Auto-package.
.DESCRIPTION
    Studio can automate the packaging of applications from creation of a project file through
    capture of the installation to the creation of the final appset with the entire process invoked from a single
    command line.
.PARAMETER config_file_path
    The path to the JSON file used to configure the auto packaging.
.PARAMETER installer_path
    The path to the executable installer which the user would like cloudpaging studio to capture
.PARAMETER working_folder
    Working folder to use when the packaged app is launched.
.PARAMETER debug_mode
    Assigning a non null value to this parameter prevents created files from being deleted

.EXAMPLE
    >studio-nip.ps1 -config_file_path c:\test\app.json
    Will automatically package the application as specified in the app.json file

    >studio-nip.ps1 -ProjectName Test -installerFile c:\test\setup.msi -OutputFolder c:\test
    Will automatically package the setup.msi application by creating an file with parameters passed in
#>

param (
    [Parameter(ParameterSetName="jsonFile", Position=0, Mandatory=$true)][string]$config_file_path,
    [Parameter(ParameterSetName="jsonFile", Position=1)][string]$installer_path=$null,
    [Parameter(ParameterSetName="jsonFile", Position=2)][string]$output_folder=$null,
    [Parameter(ParameterSetName="jsonFile", Position=3)][string]$working_folder=$null,
    [Parameter(ParameterSetName="jsonFile", Position=4)][string]$debug_mode=$null
)

$NIPS_VERSION = 1.0         #Version number for nips, this will be stored in revnotes
$SUPORTED_JSON = 1.0, 1.1   #Add supported version in array

$studioIni = $null
$script:createdFiles = @()

$rootDrive = Split-Path -Path $config_file_path -Qualifier
$studioPath = "$rootDrive\" + "Program Files\Numecent\Cloudpaging Studio\"
if(-NOT (Test-Path -Path $studioPath)){
    $studioPath = "C:\Program Files\Numecent\Cloudpaging Studio\"
}


Get-ChildItem -Path "$studioPath\lib" -Filter *.dat | ForEach-Object {
    Set-ItemProperty -Path $_.FullName -Name IsReadOnly -Value $false
}

$studioCmd = $studioPath+"JukeboxStudio.exe"
$studioPrep = $studioPath+"CloudpagingStudio-prep.ps1"
$fileDAT = $studioPath+"lib\filefilt.dat"
$regDAT = $studioPath+"lib\regfilt.dat"
$procexDAT = $studioPath + "lib\procexcluded.dat"
$procfiltDAT = $studioPath + "lib\procfilt.dat"
$defprocsDAT = $studioPath + "lib\defprocsel.dat"
$fileexcDAT = $studioPath + "lib\fileexcluded.dat"
$regexDAT = $studioPath + "lib\regexcluded.dat"

$json = $null
$WorkingFolder = "C:\"

function Format-String {
#removes excess ' " ' if necessary and is safe against null input (Won't throw null method error)
    param(
      [parameter(ValueFromPipeline)]
      [psobject] $inputObject
    )

    if($inputObject){
        #to execute when input is not null
        return $inputObject.Replace("`"","")
    }

    return $inputObject
}

function Initialize-InstallWrapper {

    $default ='@ECHO OFF
SET SOURCE=%~dp0
SET SOURCE=%SOURCE:~0,-1%

'

    $batPath = $installer_path
    $installerName = Split-Path $batPath -Leaf
    $batPath = $batPath.Replace($installerName, "Installer.bat")

    $inst = "`"$($json.CaptureCommands.InstallerPath)`""
    $InstallCommand = "" + $json.CaptureCommands.InstallerPrefix + $inst + $json.CaptureCommands.InstallerCommands + "`n"

    $batString = $default + $installCommand

    $batString = $batString.Replace("^INSTALLER_NAME^","$installerName")

    If($json.CaptureCommands.PostInstallActions.Enabled){
        $customString = $json.CaptureCommands.PostInstallActions.Commands | Out-String
        $batString = $batString + $customString
    }

    $batString | Out-String | Out-File -FilePath $batPath -Encoding ascii
    $script:createdFiles += $batPath

    return $batPath;
}

function Get-ServiceString {
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string] $StpFile
    )
    #Find file that contains MERGE_RESULTS
    #skip lines 0, 1, 2
    #Read lines until * is reached

    $path = (get-item $StpFile).Directory.Parent.FullName
    $result = Get-ChildItem -Path $path -Recurse -Filter "*MERGE_RESULTS*"
    $mergeLogPath = $output_folder + "/$result"

    $linect = 0
    $servicesString = ""

    foreach($line in Get-Content $mergeLogPath) {
        $linect = $linect + 1

        if($linect -le 3){
            Continue #ignore header portion
        }
        elseif($line -match "\*"){
            break #once next header is encountered end loop
        }
        $servicesString += "$line`n"

    }

    return $servicesString

}

function Get-RevNote{
    Param(
        [Parameter(Mandatory=$true, Position=0)]
        [string] $stpFile
    )

    $date = Get-Date


    $instPath = $json.CaptureCommands.InstallerPath
    $fileName = Split-Path $instPath -Leaf

    $services = Get-ServiceString($stpFile)
    $osString = ""
    foreach($elem in $json.ProjectSettings.TargetOS){
        $osString += $elem + ", "
    }
    $osString = $osString.TrimEnd(", ")


    $revNotesText = @"
# Numecent NIPS Revision Notes v1.0

NIPS_Version = $NIPS_VERSION
JSON_Version = $($json.JsonConfigVersion)
Date_Packaged = $date
Platform_Packaged_On = $osString
File_Name = $fileName
Compression = $($json.OutputSettings.CompressionMethod)
Encryption = $($json.OutputSettings.EncryptionMethod)

#|--------------------------------------------------------|
#|                  Services Captured                     |
#|--------------------------------------------------------|
$services
"@

    $zipName = Split-Path $stpFile -Leaf
    $zipName = $zipName.Replace(".stp",".zip")

    Rename-Item -Path $StpFile -NewName $zipName
    $zipFile = $stpFile.Replace(".stp",".zip")

    $notePath = $output_folder + "\RevNotes.txt"

    $noteString = $revNotesText
    $noteString |Out-String | Out-File -FilePath $notePath

    $stpName = Split-Path $StpFile -Leaf

    Compress-Archive -Path $notePath -Update -DestinationPath $zipFile


    Rename-Item -Path $zipFile -NewName $stpName
    Remove-Item -Path $NotePath
}

function Restore-Dat {
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string] $datFile
    )

    If (Test-Path -Path $datFile".bak")
    {
        Copy-Item -Path $datFile".bak" -Destination $datFile -Force
        Remove-Item -Path $datFile".bak"
    }
}

function Initialize-RegData{

    $installer = Split-Path $installer_path -Leaf

    $regFileCt = 0
    #ModifyKeys
    foreach($entry in $json.ModifyAssets.ModifyKeys.PSObject.Properties.name){
        if($null -eq $json.ModifyAssets.AddFiles.PSObject.Properties.name){
            break
        }

        $Location = $json.ModifyAssets.ModifyKeys.PSObject.Properties[$entry].value.PSObject.Properties["Location"].value
        $Keys = $json.ModifyAssets.ModifyKeys.PSObject.Properties[$entry].value.PSObject.Properties["Keys"].value

        $regString = "Windows Registry Editor Version 5.00`n`n"
            foreach($line in $Keys){
                $pos = $line.IndexOf("=")
                $one = $line.Substring(0, $pos)
                $two = $line.Substring($pos+1)
                $regString += "[$Location]`n"
                $regString += "`"$one`"=$two`n`n"
            }

        if($debug_mode){
            Write-Output "Creating registry file:`n"
            Write-Output $regString
        }

        $name = "reg_changes$regFileCt.reg"
        $tempDestination = $installer_path.Replace($installer, $name)
        $regString | Out-File -FilePath $tempDestination -Encoding ascii
        $script:createdFiles += $tempDestination
        Add-Content $installer_path "regedit /s `"$tempDestination`"`n"
        $regFileCt++
    }
}

function Initialize-FileData{

    $installer = Split-Path $installer_path -Leaf

    #AddFiles
    foreach($entry in $json.ModifyAssets.AddFiles.PSObject.Properties.name){
        if($null -eq $json.ModifyAssets.AddFiles.PSObject.Properties.name){
            Write-Output "No key modifications found"
            break
        }

        #$Location = $json.ModifyAssets.ModifyKeys.PSObject.Properties[$entry].value.PSObject.Properties["Location"].value
        $name = $json.ModifyAssets.AddFiles.PSObject.Properties[$entry].value.PSObject.Properties["Name"].value
        $destination = $json.ModifyAssets.AddFiles.PSObject.Properties[$entry].value.PSObject.Properties["Destination"].value
        $content = $json.ModifyAssets.AddFiles.PSObject.Properties[$entry].value.PSObject.Properties["Content"].value | Out-String

        $tempDestination = $installer_path.Replace($installer, $name)
        if($debug_mode){
            Write-Output "Creating custom file: $name at $destination"
        }

        $content | Out-File -FilePath $tempDestination -Encoding ascii
        $script:createdFiles += $tempDestination

        Add-Content $installer_path "COPY `"$tempDestination`" `"$destination`" `n"
    }

}

function Invoke-PreCaptureScript{

    $installerName = Split-Path $installer_path -Leaf

    $scriptPath = $installer_path.Replace($installerName, "prescript.bat")
    $json.PreCaptureCommands | Out-String | Out-File -FilePath $ScriptPath -Encoding ascii

    if($debug_mode){
        Write-Output "Creating pre-capture script..."
    }

    $script = Start-Process -FilePath $scriptPath -Verb runas -Wait -PassThru
    $script:createdFile

    if($script.ExitCode -eq 0)
    {
        return
    }
    else
    {
        Write-Output "WARNING: The pre capture instructions did not exit properly"
        $err = $script.ExitCode
        Write-Output "*$p Exit Code: $err*"
        return
    }
}

# Requires Administrator Rights
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Throw "You do not have Administrator rights to run this script.`nPlease re-run this script as an Administrator."
}

# Verify Studio is installed and UAC is disabled
if (-NOT (Test-Path -Path $studioCmd))
{
    Throw "Cloudpaging Studio was not found to be installed at location: $studioPath"
}
if ((Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).EnableLUA) {
    Throw "Windows user access control (UAC) is enabled on this machine and can interfere with automated packaging."
}


# Verify the parameter


$processIni = $true
switch ($PsCmdlet.ParameterSetName)
{
    "jsonFile"  {
                    if (!$config_file_path)
                    {
                        Throw 'Missing parameter: $config_file_path'
                    }

                    # Verify the JSON file can be found
                    if (-NOT (Test-Path -Path $config_file_path))
                    {
                        Throw "JSON file does not exist: $config_file_path"
                    }

                    $studioIni = $config_file_path
                     $studioLog ="$([io.path]::getdirectoryname($config_file_path))\" + "$([io.path]::GetFileNameWithoutExtension($config_file_path))_NIP.log"
                    # Read the INI for a project name

                    $json = Get-Content $config_file_path | ConvertFrom-Json


                    [double]$version = $json.JsonConfigVersion -as [double]

                    if($SUPORTED_JSON.Contains($version))
                    {
                       Write-Output "Reading config file version: $($json.JsonConfigVersion)"
                    }
                    else
                    {
                        $min = $SUPORTED_JSON | Measure-Object -Minimum
                        if($min -gt $version)
                        {
                            Write-Output "WARNING: This configuration file is no longer supported, would you like to continue anyways?"
                        }else
                        {
                            Write-Output "WARNING: This configuration file request a newer version of NIPS, would you like to continue anyways?"
                        }

                        Write-Output "Press `"Enter`" to continue or `"Ctrl-C`" to cancel"
                            do
                            {
                                $key = [Console]::ReadKey("noecho")
                            }while($key.Key -ne "Enter")
                    }

                    ####set required settings here###
                    #   '#' = Not currently being communicated to cloudpaging studio

                        if(!$installer_path)
                        {
                            $installer_path = $json.CaptureCommands.InstallerPath | Format-String
                        }
                        if(!$output_folder)
                        {
                            $output_folder = $json.OutputSettings.OutputFolder  | Format-String
                        }
                        #make sure output folder ends in '\'
                        if(-NOT ($output_folder -match '\\$'))
                        {
                            $output_folder =$output_folder + '\'
                        }

                        $WorkingFolder = ""
                        if(!$working_folder)
                        {
                            $WorkingFolder = $working_folder
                        }elseif(!($json.ProjectSettings.WorkingFolder))
                        {
                            $WorkingFolder = $json.ProjectSettings.WorkingFolder | Format-String
                        }

                        $ProjectDescription = $json.ProjectSettings.ProjectDescription | Format-String
                        #$ProjectFileName = $json.ProjectSettings.ProjectFileName | Format-String
                        #$ProjectFolder = $json.ProjectSettings.ProjectFolder | Format-String
                        $CompressionMethod = $json.OutputSettings.CompressionMethod  | Format-String
                        $EncryptionMethod = $json.OutputSettings.EncryptionMethod | Format-String
                        $CommandLine = $json.ProjectSettings.CommandLine  | Format-String
                        $CommandLineParams = $json.ProjectSettings.CommandLineParams
                        #$IconFile = $json.ProjectSettings.IconFile  | Format-String
                        #$EulaFile = $json.ProjectSettings.EulaFile  | Format-String

                        $CaptureAllProcesses = "No"
                        if($json.CaptureSettings.CaptureAllProcesses)
                        {
                            $CaptureAllProcesses = "Yes"
                        }
                        #$IgnoreChangesUnderInstallerPath = $json.CaptureSettings.IgnoreChangesUnderInstallerPath
                        #$ReplaceRegistryShortPaths = $json.CaptureSettings.ReplaceRegistryShortPaths
                        $CaptureTimeout = $json.CaptureSettings.CaptureTimeoutSec
                        $DefaultDispositionLayer = $json.VirtualizationSettings.DefaultDispositionLayer
                        #$OutputFileNameNoExt =
                        #$FinalizeIntoSTP = $json.PackagingSettings.FinalizeIntoSTP  | Format-String

                        ##if indicated, create a bat file


                        if ($json.CaptureCommands.Enabled)
                        {
                            $installer_path = Initialize-InstallWrapper
                            Write-Output "Installer path is $installer_path"
                        }
                        if ($null -ne $json.ModifyAssets.ModifyKeys.PSObject.Properties.name){
                            if($debug_mode){
                                Write-Output "Initilizing Registry Data...."
                            }
                            Initialize-RegData
                        }
                        if ($null -ne $json.ModifyAssets.AddFiles.PSObject.Properties.name)
                        {
                                if($debug_mode){
                                    Write-Output "Initilizing File Data...."
                                }
                                Initialize-FileData
                        }
                        if ($json.PreCaptureCommands)
                        {
                                Invoke-PreCaptureScript
                        }

                    $ProjectName = $json.ProjectSettings.ProjectName.Replace("`"","")

                    # Find DAT file filter updates
                    if ($json.CaptureSettings.FileExclusions)
                    {
                        # Back the DAT file
                        if (-NOT (Test-Path -Path $fileDAT".bak"))
                        {
                            Write-Output "Backing up $fileDAT"
                            Copy-Item -Path $fileDAT -Destination $fileDAT".bak"
                        }

                        # Append DAT files
                        Add-Content $fileDAT "`r`n`n# -------------------------"
                        Add-Content $fileDAT "`n# Filters for $ProjectName`n"
                        #Create Output String and format for writing to DAT file

                        $OutputString = ""
                        $Name = "NIPS_FILE_EX"
                        $index = 1
                        foreach($entry in $json.CaptureSettings.FileExclusions)
                        {
                            $entry = $entry.Trim()
                            $n = $Name + $index
                            $index++
                            $OutputString += $n + "`t`t" + $entry + "`n"
                        }

                        $OutputString | Out-String | Add-Content $fileDAT
                    }

                    # Find DAT registry filter updates
                    if ($json.CaptureSettings.RegistryExclusions)
                    {

                        #Surroud the values in quotes when they contain spaces

                        # Back the DAT file
                        if (-NOT (Test-Path -Path $regDAT".bak"))
                        {
                            Write-Output "Backing up $regDAT"
                            Copy-Item -Path $regDAT -Destination $regDAT".bak"
                        }

                        # Append DAT files
                        Add-Content $regDAT "`r`n`n# -------------------------"
                        Add-Content $regDAT "`n# Filters for $ProjectName`n"
                        #Create Output String and format for writing to DAT file

                        $OutputString = ""
                        $Name = "NIPS_REG_EX"
                        $index = 1
                        foreach($entry in $json.CaptureSettings.RegistryExclusions)
                        {
                            $n = $Name + $index
                            $index++
                            $entry = $entry.Trim()

                            if($entry -match " ")
                            {
                                $OutputString += $n + "`t" + "`"$($entry)`"`n"
                            }
                            else
                            {
                                $OutputString += $n + "`t" + $entry + "`n"
                            }
                        }

                        $OutputString | Out-String | Add-Content $regDAT
                    }

                    # Find DAT process exclusion filter updates
                    if ($json.CaptureSettings.ProcessExclusions)
                    {
                        #Surroud the values in quotes when they contain spaces

                        # Back the DAT file
                        if (-NOT (Test-Path -Path $procexDAT".bak"))
                        {
                            Write-Output "Backing up $procexDAT"
                            Copy-Item -Path $procexDAT -Destination $procexDAT".bak"
                        }

                        # Append DAT files
                        Add-Content $procexDAT "`r`n`n# -------------------------"
                        Add-Content $procexDAT "`n# Filters for $ProjectName`n"
                        #Create Output String and format for writing to DAT file
                        $OutputString = ""
                        foreach($entry in $json.CaptureSettings.ProcessExclusions)
                        {
                            if($entry -match " ")
                            {
                                $OutputString += "`"$($entry)`"`n"
                            }
                            else
                            {
                                $OutputString += $entry + "`n"
                            }
                        }


                        $OutputString | Out-String | Add-Content $procexDAT
                    }

                    # Find DAT process filter updates
                    if ($json.CaptureSettings.ProcessInclusions.Include)
                    {

                        #Surroud the values in quotes when they contain spaces

                        # Back the DAT file
                        if (-NOT (Test-Path -Path $procfiltDAT".bak"))
                        {
                            Write-Output "Backing up $procfiltDAT"
                            Copy-Item -Path $procfiltDAT -Destination $procfiltDAT".bak"
                        }

                        # Append DAT files
                        Add-Content $procfiltDAT "`n# Filters for $ProjectName"
                        #Create Output String and format for writing to DAT file
                        $OutputString = ""
                        $bool = "TRUE"
                        if(-NOT ($json.CaptureSettings.ProcessInclusions.IncludeChildProccesses))
                        {
                            $bool = "FALSE"
                        }

                        foreach($entry in $json.CaptureSettings.ProcessInclusions.Include)
                        {

                            if($entry -match " ")
                            {
                                $OutputString += "`"$($entry)`"`t`t" + $bool + "`n"
                            }
                            else
                            {
                                $OutputString += $entry + "`t`t" + $bool + "`n"
                            }
                        }

                        $OutputString | Out-String | Add-Content $procfiltDAT
                    }
                                                            # Find DAT process filter updates
                    if ($json.SecurityOverrideSettings.AllowAccessLayer4.Proccesses -Or $json.SecurityOverrideSettings.DenyAccessLayer3) ##!!
                    {
                        # Back the DAT file
                        if (-NOT (Test-Path -Path $defprocsDAT".bak"))
                        {
                            Write-Output "Backing up $defprocsDAT"
                            Copy-Item -Path $defprocsDAT -Destination $defprocsDAT".bak"
                        }

                        #Check if DAT entry needs update
                        $file_text = Get-Content $defprocsDAT
                        $json.SecurityOverrideSettings.PSObject.Properties.Name | ForEach-Object{
                            $wordSearch = $_;                                     #current key in loop
                            $containsWord = $file_text | ForEach-Object{$_ -match $wordSearch} #if we match that key

                            if($containsWord -contains $true)
                            {  #comments out key
                                    ($file_text) | ForEach-Object {$_ -replace $wordSearch, "# $wordSearch"} |  Set-Content $defprocsDAT
                            }
                        }


                        # Append DAT files
                        Add-Content $defprocsDAT "`r`n`n# -------------------------"
                        Add-Content $defprocsDAT "`n# Settings for $ProjectName`n"
                        #Create Output String and format for writing to DAT file
                        $OutputString = ""
                        $bool = "TRUE"
                        if(-NOT ($json.SecurityOverrideSettings.AllowAccessLayer4.AllowReadAndCopy))
                        {
                            $bool = "FALSE"
                        }

                        foreach($proc in $json.SecurityOverrideSettings.AllowAccessLayer4.Proccesses)
                        {
                            $OutputString += "$proc`t`tTRUE`t$bool`n"
                        }
                        foreach($proc in $json.SecurityOverrideSettings.DenyAccessLayer3)
                        {
                            $OutputString += "$proc`t`tFALSE`n"
                        }

                        $OutputString | Out-String | Add-Content $defprocsDAT
                    }
                    if ($json.VirtualizationSettings.SandboxFileExclusions)
                    {
                        # Back the DAT file
                        if (-NOT (Test-Path -Path $fileexcDAT".bak"))
                        {
                            Write-Output "Backing up $fileexcDAT"
                            Copy-Item -Path $fileexcDAT -Destination $fileexcDAT".bak"
                        }

                        # Append DAT files
                        Add-Content $fileexcDAT "`r`n`n# -------------------------"
                        Add-Content $fileexcDAT "`n# Settings for $ProjectName`n"
                        #Create the String and format for writing to DAT file
                        $OutputString = $json.VirtualizationSettings.SandboxFileExclusions | Out-String
                        $OutputString | Out-String | Add-Content $fileexcDAT
                    }
                    if ($json.VirtualizationSettings.SandboxRegistryExclusions)
                    {
                        # Back the DAT file
                        if (-NOT (Test-Path -Path $regexDAT".bak"))
                        {
                            Write-Output "Backing up $regexDAT"
                            Copy-Item -Path $regexDAT -Destination $regexDAT".bak"
                        }

                        # Append DAT files
                        Add-Content $regexDAT "`r`n`n# -------------------------"
                        Add-Content $regexDAT "`n# Settings for $ProjectName`n"
                        #Create Output String and format for writing to DAT file
                        $OutputString = $json.VirtualizationSettings.SandboxRegistryExclusions | Out-String
                        $OutputString | Out-String | Add-Content $regexDAT
                    }
                    break
                }
    "inputVal" {
                    if (!$ProjectName)
                    {
                        Throw 'Missing parameter: $ProjectName'
                    }
                    if (!$output_folder)
                    {
                        Throw 'Missing parameter: $output_folder'
                    }
                    if (!$installer_path)
                    {
                        Throw 'Missing parameter: $installer_path'
                    }
                    # Verify the installer can be found
                    if (-NOT (Test-Path -Path $installer_path))
                    {
                        Throw "Installer file does not exist: $installer_path"
                    }
                    # Verify the output path exists
                    if (-NOT (Test-Path -Path $output_folder))
                    {
                        Throw "Output path does not exist: $output_folder"
                    }

                    $studioIni = "$($output_folder)$($ProjectName).ini"
                    $studioLog = "$($output_folder)$($ProjectName).log"
                    break
                }
    default { Throw "No valid parameters passed" }
}


# Define the input INI packaging file
$functionText = @"
[ProjectSettings]
ProjectName="$ProjectName"
ProjectDescription="$ProjectDescription"
ProjectFolder="$output_folder"
TargetOS=$TargetOS
CompressionMethod=$CompressionMethod
EncryptionMethod=$EncryptionMethod
CommandLine="$CommandLine"
WorkingFolder="$WorkingFolder"

[CaptureSettings]
InstallerPath="$installer_path"
CommandLineParams="$CommandLineParams"
CaptureAllProcesses=$CaptureAllProcesses
CaptureTimeout=$CaptureTimeout
DefaultDispositionLayer=$DefaultDispositionLayer
DefaultServiceVirtualizationAction=$DefaultServiceVirtualizationAction

[PackagingSettings]
OutputFolder="$output_folder"
"@

# Execute the Cloudpaging-prep script, if present
if (Test-Path -Path $studioPrep)
{
#    & "$studioPrep" true
}

Write-Output "Starting to package $ProjectName automatically..."

# Create the input INI packaging file
if ($processIni)
{
    $i = Split-Path $installer_path -Leaf
    $studioIni = $installer_path.Replace($i,"studio_config.ini")
    $script:createdFiles += $studioIni
    Write-Output "Creating non-interactive packaging INI as $studioIni"
    New-Item $studioIni -type file -force -value $functionText | Out-Null
} else {
    Write-Output "Input file is $studioIni"
}
Write-Output "Output log file is $studioLog "

# Call Studio to package non-interactively
Write-Output "Starting Studio for non-interactive packaging..."

$process = Start-Process -FilePath $studioCmd -ArgumentList "-a ""$studioIni""  -l ""$studioLog"" " -Verb runas -Wait -PassThru
#Start-Sleep -s 10

# Reverse changes to DAT files
if(-NOT ($debug_mode))
{
    Restore-Dat($fileDAT)
    Restore-Dat($regDAT)
    Restore-Dat($defprocsDAT)
    Restore-Dat($regexDAT)
    Restore-Dat($procexDAT)
    Restore-Dat($procfiltDAT)
    Restore-Dat($procfiltDAT)
    Restore-Dat($fileexcDAT)
}
# Check if packaging was successful
if ($process.ExitCode -eq 0)
{
    if ($processIni)
    {
        $ProjectName = $ProjectName.Replace("`"","") #Ensure there are no extra quotes
        $appset = $output_folder + $ProjectName + ".stp"
    }
    else
    {
        $IniLine = Get-Content -Path $studioIni | Where-Object { $_ -match 'OutputFolder=' }
        $appsetPath = $IniLine.Split('=')[1].Replace("`"","")
        $appset =  Get-ChildItem -Path $appsetPath -Filter *.stp -ErrorAction SilentlyContinue
        $appset = $appsetPath + $appset
    }
    # Verify output file exists
    if (-NOT (Test-Path -Path $appset))
    {
        Write-Warning "Application package was not found: $appset"
        return
    }
    else
    {
        $appsetSize = ((Get-Item $appset).length/1GB)
        if($appsetSize -lt 4){
            Get-RevNote($appset)
        }

        Write-Output "Completed packaging successfully..."
        Write-Output "Package can be found at: $appset"

        if(-NOT ($debug_mode)){
            foreach($file in $script:createdFiles){
                Remove-Item -Path $file
            }
        }
    }
}
else
{
    $packageError = "Error packaging: 0x" + [Convert]::ToString($process.ExitCode, 16)
    Write-Warning -Message $packageError
    switch ([Convert]::ToString($process.ExitCode, 16))
    {
        A0046010 { Write-Warning "Failed to retrieve current directory" }
        A0046020 { Write-Warning "Failed to create document" }
        A0046021 { Write-Warning "Failed to open document" }
        A0046022 { Write-Warning "Failed to save document" }
        A0046023 { Write-Warning "Failed to generate application ID" }
        A0046024 { Write-Warning "Failed to set application ID" }
        A0046025 { Write-Warning "Failed to set application name" }
        A0046300 { Write-Warning "Capture failed" }
        A0046400 { Write-Warning "Merge failed" }
        A0046500 { Write-Warning "Packaging failed" }
        A0046501 { Write-Warning "Failed to replace stage-1 prefetch during packaging" }
        A0046502 { Write-Warning "Failed to merge stage-1 prefetch during packaging" }
        A0046503 { Write-Warning "Failed to replace stage-2 prefetch during packaging" }
        A0046504 { Write-Warning "Failed to merge stage-2 prefetch during packaging" }
        A0046505 { Write-Warning "Specified output path is invalid" }
        A0046506 { Write-Warning "Specified output file is a folder" }
        A0046507 { Write-Warning "Failed to add root folder" }
        A0046600 { Write-Warning "Invalid parameter for configuration file" }
        A0046601 { Write-Warning "Configuration file does not exist or cannot be accessed" }
        A0046610 { Write-Warning "A required setting is missing" }
        A0046611 { Write-Warning "Invalid value (value is properly formatted but not within acceptable set/range)" }
        A0046612 { Write-Warning "Improperly formatted value or parsing error" }
        a0046013 { Write-Warning "Value not recognized" }
        default  { Write-Warning "An unspecified error occurred" }
    }
    Write-Warning "Please see output log for details"
    Throw $process.ExitCode
}

return
