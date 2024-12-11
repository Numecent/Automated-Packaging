#   Cloudpaging Studio - Automated NIP (Non-interactive Packaging)
#
#   Copyright (c) 2023 Numecent, Inc.  All rights reserved.
#
#   This file is an unpublished work and the proprietary and confidential
#   information of Numecent.  Should this source code become published,
#   it is entitled to the fullest protection under the copyright laws,
#   as it was created as early as 1996, and continues to be updated and
#   owned by Numecent. Use, disclosure, reproduction, or distribution is
#   prohibited except as permitted by express written license agreement
#   with Numecent Inc.
#
# Revision January 26, 2023

<#
.SYNOPSIS
    Numecent Studio non-interactive packaging.
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
.PARAMETER appset_name
    Name for the .stp appset, do not include an extension. Used instead of OutputSettings.OutputFileNameNoExt
.PARAMETER debug_mode
    Assigning a non null value to this parameter prevents created files from being deleted

.EXAMPLE
    >studio-nip.ps1 -config_file_path 'c:\test\app.json'
    Will automatically package the application as specified in the app.json file

    >studio-nip.ps1 -config_file_path 'c:\test\app.json' -installer_path 'C:\test\installer.exe' -output_folder 'C:\test\Output'
    Will automatically package the installer.exe application as specified by the app.json file, and place the output files in the specified location
#>

param (
    [Parameter(ParameterSetName="jsonFile", Position=0, Mandatory=$true)][string]$config_file_path,
    [Parameter(ParameterSetName="jsonFile", Position=1)][string]$installer_path=$null,
    [Parameter(ParameterSetName="jsonFile", Position=2)][string]$output_folder=$null,
    [Parameter(ParameterSetName="jsonFile", Position=3)][string]$working_folder=$null,
    [Parameter(ParameterSetName="jsonFile", Position=4)][string]$appset_name=$null,
    [Parameter(ParameterSetName="jsonFile", Position=5)][string]$debug_mode=$null
)

$NIPS_VERSION = 1.0                   #Version number for nips, this will be stored in revnotes
$SUPORTED_JSON = 1.0, 1.1, 1.2, 1.3   #Add supported version in array

$studioIni = $null
$script:createdFiles = @()          #List of files created in automated packaging
$script:versionNumber = $null       #Cloudpaging Studio Version

$rootDrive = Split-Path -Path $config_file_path -Qualifier
$studioPath = "$rootDrive\" + "Program Files\Numecent\Cloudpaging Studio\"
if(-NOT (Test-Path -Path $studioPath)){
    $studioPath = "C:\Program Files\Numecent\Cloudpaging Studio\"
}

Get-ChildItem -Path "$studioPath\lib" -Filter *.dat | ForEach-Object {
    Set-ItemProperty -Path $_.FullName -Name IsReadOnly -Value $false
}

$studioCmd = $studioPath + "JukeboxStudio.exe"              #Execute Automated Packaging
$studioPrep = $studioPath + "CloudpagingStudio-prep.ps1"    #Store downloaded prep scripts here

$fileDAT = $studioPath + "lib\filefilt.dat"                 # File Exclusions         ($json.CaptureSettings.FileExclusion)
$regDAT = $studioPath + "lib\regfilt.dat"                   # Registry Exclusions     ($json.CaptureSettings.RegistryExclusions)
$procexDAT = $studioPath + "lib\procexcluded.dat"           # Process Exclusions      ($json.CaptureSettings.ProcessExclusions)
$procfiltDAT = $studioPath + "lib\procfilt.dat"             # Process Inclusion       ($json.CaptureSettings.ProcessInclusions.Include)
$defprocsDAT = $studioPath + "lib\defprocsel.dat"           # Security Override       ($json.SecurityOverrideSettings)
$fileexcDAT = $studioPath + "lib\fileexcluded.dat"          # Sandbox File Exclusions ($json.VirtualizationSettings.SandboxFileExclusions)
$regexDAT = $studioPath + "lib\regexcluded.dat"             # Sandbox Reg Exclusions  ($json.VirtualizationSettings.SandboxRegistryExclusions)
$regDispoDAT = $studioPath + "lib\regdispositions.dat"      # Registry Dispo Layers   ($json.VirtualizationSettings.RegistryDispositionLayers)
$fileDispoDAT = $studioPath + "lib\filedispositions.dat"    # File Dispo Layers       ($json.VirtualizationSettings.FileDispositionLayers)

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

    $inst = "`"$installer_path`""
    $InstallCommand = "" + $json.CaptureCommands.InstallerPrefix + $inst + $json.CaptureCommands.InstallerCommands + "`n"

    $batString = $default + $installCommand

    $batString = $batString.Replace("^INSTALLER_NAME^","$installerName")

    if($json.CaptureCommands.PostInstallActions.Enabled){
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
    $mergeName = Split-Path $stpFile -Leaf
    $mergeName = $mergeName.Replace(".stp","*MERGE_RESULTS*")
    $result = Get-ChildItem -Path $path -Recurse -Filter "$mergeName"

    if ($result.count -gt 1){
        #Get latest result with matching name
        $result = Get-ChildItem -Path $path -Recurse -Filter "$mergeName" | Sort-Object LastAccessTime -Descending | Select-Object -First 1
    }
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
Studio_Version = $script:versionNumber
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

If((Get-ChildItem $stpFile).length -lt 2000000000){
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
    else
    {
    $notePath = $output_folder + "\RevNotes.txt"
    $noteString = $revNotesText
    $noteString |Out-String | Out-File -FilePath $notePath
    }
}
function Backup-Dat {
    #Create a .bak backup file of the dat
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $datFile
    )

    if (-NOT (Test-Path -Path $datFile".bak")) {
        Write-Output "Backing up $datFile"
        Copy-Item -Path $datFile -Destination $datFile".bak"
    }
}
function Restore-Dat {
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string] $datFile
    )

    if(Test-Path -Path $datFile".bak")
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
        if($null -eq $json.ModifyAssets.ModifyKeys.PSObject.Properties.name){
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
	$filedataDestinationTest = Test-path $destination 
	if ($filedataDestinationTest -eq $false){
	New-item $destination -ItemType directory > $null -Force
	}
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

function Add-Folders{
    if($debug_mode){
        Write-Output "Add folders..."
    }

    $addFolderCnt = 1
    $folderSection = ""

    foreach($entry in $json.PostCaptureCommands.AddFolders.PSObject.Properties.name){
        $sourcePath = $json.PostCaptureCommands.AddFolders.PSObject.Properties[$entry].value.PSObject.Properties["SourcePath"].value
        $destinationPath = $json.PostCaptureCommands.AddFolders.PSObject.Properties[$entry].value.PSObject.Properties["DestinationPath"].value
        $includeSubfolders = "Yes"
        if(!$json.PostCaptureCommands.AddFolders.PSObject.Properties[$entry].value.PSObject.Properties["IncludeSubfolders"].value){
            $includeSubfolders = "No"
        }
        $includeFilesInFolders = "Yes"
        if(!$json.PostCaptureCommands.AddFolders.PSObject.Properties[$entry].value.PSObject.Properties["IncludeFilesInFolders"].value){
            $includeFilesInFolders = "No"
        }

        $sectionText = @"

[AddFolder$addFolderCnt]
SourcePath="$sourcePath"
DestinationPath="$destinationPath"
IncludeSubfolders=$includeSubfolders
IncludeFilesInFolders=$includeFilesInFolders

"@
        $folderSection += $sectionText
        $addFolderCnt++
    }

    return $folderSection
}

function Add-Keys{
    if($debug_mode){
        Write-Output "Add keys..."
    }

    $addKeysCnt = 1
    $keysSection = ""

    foreach($entry in $json.PostCaptureCommands.AddKeys.PSObject.Properties.name){
        $sourceKey = $json.PostCaptureCommands.AddKeys.PSObject.Properties[$entry].value.PSObject.Properties["SourceKey"].value
        $destinationKey = $json.PostCaptureCommands.AddKeys.PSObject.Properties[$entry].value.PSObject.Properties["DestinationKey"].value
        $includeSubkeys = "Yes"
        if(!$json.PostCaptureCommands.AddKeys.PSObject.Properties[$entry].value.PSObject.Properties["IncludeSubkeys"].value){
            $includeSubkeys = "No"
        }
        $includeValuesInKeys = "Yes"
        if(!$json.PostCaptureCommands.AddKeys.PSObject.Properties[$entry].value.PSObject.Properties["IncludeValuesInKeys"].value){
            $includeValuesInKeys = "No"
        }

        $sectionText = @"

[AddKey$addKeysCnt]
SourceKey="$sourceKey"
DestinationKey="$destinationKey"
IncludeSubkeys=$includeSubkeys
IncludeValuesInKeys=$includeValuesInKeys

"@
        $keysSection += $sectionText
        $addKeysCnt++
    }

    return $keysSection
}

# Requires Administrator Rights
if(-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Throw "You do not have Administrator rights to run this script.`nPlease re-run this script as an Administrator."
}

# Verify Studio is installed and UAC is disabled
if(-NOT (Test-Path -Path $studioCmd))
{
    Throw "Cloudpaging Studio was not found to be installed at location: $studioPath"
}
if((Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).EnableLUA) {
    Throw "Windows user access control (UAC) is enabled on this machine and can interfere with automated packaging."
}

$script:versionNumber = [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$studioCmd").FileVersion
Write-Output "Cloudpaging Studio Version: $script:versionNumber"

# Verify the parameter
$processIni = $true
switch ($PsCmdlet.ParameterSetName)
{
    "jsonFile"  {
                    if(!$config_file_path)
                    {
                        Throw 'Missing parameter: $config_file_path'
                    }

                    # Verify the JSON file can be found
                    if(-NOT (Test-Path -Path $config_file_path))
                    {
                        Throw "JSON file does not exist: $config_file_path"
                    }

                    $studioIni = $config_file_path
                    $studioLog ="$([io.path]::getdirectoryname($config_file_path))\" + "$([io.path]::GetFileNameWithoutExtension($config_file_path))_NIP.log"

                    # Read the JSON file for project settings
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
                        }
                        else
                        {
                            Write-Output "WARNING: This configuration file request a newer version of NIPS, would you like to continue anyways?"
                        }

                        Write-Output "Press `"Enter`" to continue or `"Ctrl-C`" to cancel"
                            do
                            {
                                $key = [Console]::ReadKey("noecho")
                            }while($key.Key -ne "Enter")
                    }

                    # Set required settings from JSON
                    if(!$installer_path)
                    {
                        $installer_path = $json.CaptureCommands.InstallerPath | Format-String
                    }
                    if(!$output_folder)
                    {
                        $output_folder = $json.OutputSettings.OutputFolder | Format-String
                    }

                    if(-NOT ($output_folder -match '\\$'))
                    {
                        # make sure output folder ends in '\'
                        $output_folder =$output_folder + '\'
                    }

                    $WorkingFolder = ""
                    if(!$working_folder)
                    {
                        $WorkingFolder = $working_folder
                    }
                    elseif(!($json.ProjectSettings.WorkingFolder))
                    {
                        $WorkingFolder = $json.ProjectSettings.WorkingFolder | Format-String
                    }

                    $ProjectDescription = $json.ProjectSettings.ProjectDescription | Format-String
                    $CompressionMethod = $json.OutputSettings.CompressionMethod | Format-String
                    $EncryptionMethod = $json.OutputSettings.EncryptionMethod | Format-String
                    $CommandLine = $json.ProjectSettings.CommandLine
                    $CommandLineParams = $json.ProjectSettings.CommandLineParams
                    $IconFile = $json.ProjectSettings.IconFile | Format-String
                    if(-NOT ([string]::IsNullOrEmpty($IconFile)))
                    {
                        $IconFile = """$IconFile"""
                    }					

                    $CaptureAllProcesses = "Yes"
                    if(!$json.CaptureSettings.CaptureAllProcesses)
                    {
                        $CaptureAllProcesses = "No"
                    }
                    $IgnoreChangesUnderInstallerPath = "Yes"
                    if(!$json.CaptureSettings.IgnoreChangesUnderInstallerPath)
                    {       
                        $IgnoreChangesUnderInstallerPath = "No"
                    }
                    $ReplaceRegistryShortPaths ="Yes"
                    if(!$json.CaptureSettings.ReplaceRegistryShortPaths)
                    {       
                        $ReplaceRegistryShortPaths = "No"
                    }
                    $CaptureTimeout = $json.CaptureSettings.CaptureTimeoutSec
                    $DefaultDispositionLayer = $json.VirtualizationSettings.DefaultDispositionLayer
                    $OutputFileNameNoExt = $json.OutputSettings.OutputFileNameNoExt
                    if($appset_name){
                        $OutputFileNameNoExt = $appset_name
                    }
                    if($OutputFileNameNoExt -match " "){
                        $OutputFileNameNoExt = "`"$OutputFileNameNoExt`""
                    }

                    $FinalizeIntoSTP = "Yes"
                    if(!$json.OutputSettings.FinalizeIntoSTP){
                        $FinalizeIntoSTP = "No"
                    }

                    # If indicated, create a bat file
                    if($json.CaptureCommands.Enabled)
                    {
                        $installer_path = Initialize-InstallWrapper
                        Write-Output "Installer path is $installer_path"
                    }
                    if($null -ne $json.ModifyAssets.ModifyKeys.PSObject.Properties.name){
                        if($debug_mode){
                           Write-Output "Initilizing Registry Data...."
                        }
                        Initialize-RegData
                    }
                    if($null -ne $json.ModifyAssets.AddFiles.PSObject.Properties.name)
                    {
                            if($debug_mode){
                                Write-Output "Initilizing File Data...."
                            }
                            Initialize-FileData
                    }
                    if($json.PreCaptureCommands)
                    {
                        Invoke-PreCaptureScript
                    }

                    $ProjectName = $json.ProjectSettings.ProjectName.Replace("`"","")

                    # Add folder
                    if($null -ne $json.PostCaptureCommands.AddFolders.PSObject.Properties.name)
                    {
                        $AddFolderSection = Add-Folders
                    }

                    # Add Keys
                    if($null -ne $json.PostCaptureCommands.AddKeys.PSObject.Properties.name)
                    {
                        $AddKeysSection = Add-Keys
                    }

                    # Find DAT file filter updates
                    if($json.CaptureSettings.FileExclusions)
                    {
                        # Back the DAT file
                        Backup-Dat $fileDAT
			
                        # Append DAT files
                        Add-Content $fileDAT "`r`n`n# -------------------------"
                        Add-Content $fileDAT "FILTER_ACTION EXCLUDE"
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
                    if($json.CaptureSettings.RegistryExclusions)
                    {

                        #Surroud the values in quotes when they contain spaces

                        # Back the DAT file
                        Backup-Dat $regDAT

                        # Append DAT files
                        Add-Content $regDAT "`r`n`n# -------------------------"
                        Add-Content $regDAT "FILTER_ACTION EXCLUDE"
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
                    if($json.CaptureSettings.ProcessExclusions)
                    {
                        #Surroud the values in quotes when they contain spaces

                        # Back the DAT file
                        Backup-Dat $procexDAT

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
                    
                    ## Format 1.1 feature backwards compatible
                    # Check if system installation processes should be captured (by default, will capture these processes)
                    if(-NOT ([string]::IsNullOrEmpty($json.CaptureSettings.IncludeSystemInstallationProcesses)) -AND -NOT ($json.CaptureSettings.IncludeSystemInstallationProcesses))
                    {
                        # Back the DAT file
                        if(-NOT (Test-Path -Path $procfiltDAT".bak"))
                        {
                            Write-Output "Backing up $procfiltDAT"
                            Copy-Item -Path $procfiltDAT -Destination $procfiltDAT".bak"
                        }
                        
                       # Captures all initial comments with #* in the process filter
                       # Will break on the first instance of anything that is not "#*"
                       Set-Content $procfiltDAT -Value $(
                       @(
                         switch -Wildcard -File $procfiltDAT {
                         '#*' { $_ }
                         default { break }
                         }
                         # Append the dummy process string to the file
                        ) + "`n`n# Dummy process inserted here", "`n EMPTY_FAKE_PROCESS.EXE"
                       )
                    }
                    # Find DAT process filter updates
                    if($json.CaptureSettings.ProcessInclusions.Include)
                    {

                        #Surroud the values in quotes when they contain spaces

                        # Back the DAT file
                        Backup-Dat $procfiltDAT
			
                        # Append DAT files
                        Add-Content $procfiltDAT "`n# Filters for $ProjectName"
                        #Create Output String and format for writing to DAT file
                        $OutputString = ""
                        $bool = "TRUE"

                        # field IncludeChildProccesses
                        if($json.CaptureSettings.ProcessInclusions.PSObject.Properties.name.Contains("IncludeChildProccesses") -and 
                           (-NOT ($json.CaptureSettings.ProcessInclusions.IncludeChildProccesses)))
                        {
                            $bool = "FALSE"
                        }
                        # field IncludeChildProcesses
                        if($json.CaptureSettings.ProcessInclusions.PSObject.Properties.name.Contains("IncludeChildProcesses") -and 
                           (-NOT ($json.CaptureSettings.ProcessInclusions.IncludeChildProcesses)))
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
                    if($json.SecurityOverrideSettings.AllowAccessLayer4.Proccesses -or
                       $json.SecurityOverrideSettings.AllowAccessLayer4.Processes -or 
                       $json.SecurityOverrideSettings.DenyAccessLayer3) ##!!
                    {
                        # Back the DAT file
                        Backup-Dat $defprocsDAT

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

                        if($json.SecurityOverrideSettings.AllowAccessLayer4.PSObject.Properties.name.Contains("Proccesses"))
                        {
                            $processes = $json.SecurityOverrideSettings.AllowAccessLayer4.Proccesses
                        }
                        else 
                        {
                            $processes = $json.SecurityOverrideSettings.AllowAccessLayer4.Processes
                        }
                        foreach($proc in $processes)
                        {
                            $OutputString += "$proc`t`tTRUE`t$bool`n"
                        }

                        foreach($proc in $json.SecurityOverrideSettings.DenyAccessLayer3)
                        {
                            $OutputString += "$proc`t`tFALSE`n"
                        }

                        $OutputString | Out-String | Add-Content $defprocsDAT
                    }
                    if($json.VirtualizationSettings.SandboxFileExclusions)
                    {
                        # Back the DAT file
                        Backup-Dat $fileexcDAT

                        # Append DAT files
                        Add-Content $fileexcDAT "`r`n`n# -------------------------"
                        Add-Content $fileexcDAT "`n# Settings for $ProjectName`n"
                        #Create the String and format for writing to DAT file
                        $OutputString = $json.VirtualizationSettings.SandboxFileExclusions | Out-String
                        $OutputString | Out-String | Add-Content $fileexcDAT
                    }
                    if($json.VirtualizationSettings.SandboxRegistryExclusions)
                    {
                        # Back the DAT file
                        Backup-Dat $regexDAT

                        # Append DAT files
                        Add-Content $regexDAT "`r`n`n# -------------------------"
                        Add-Content $regexDAT "`n# Settings for $ProjectName`n"
                        #Create Output String and format for writing to DAT file
                        $OutputString = $json.VirtualizationSettings.SandboxRegistryExclusions | Out-String
                        $OutputString | Out-String | Add-Content $regexDAT
                    }
                    if ($json.VirtualizationSettings.FileDispositionLayers -AND ($script:versionNumber -ge 9.2)) {
                        # Back the DAT file
                        Backup-Dat $fileDispoDAT
			
                        $OutputString = "`n"
                        $json.VirtualizationSettings.FileDispositionLayers.PSObject.Properties | ForEach-Object {
                            $path = $_.PSObject.Properties.Value.Path
                            if ($path -match " ") {
                                $path = "`"$path`""
                                $path = $path.Replace("\", "\\")
                            }
                            $OutputString += "$path`t`t $($_.PSObject.Properties.Value.Layer)`t`t $($_.PSObject.Properties.Value.Recurse)`n"
                        }
                        $OutputString = $OutputString -ireplace [regex]::Escape("True"), "TRUE"
                        $OutputString = $OutputString -ireplace [regex]::Escape("False"), "FALSE"
                        $OutputString | Out-String | Add-Content $fileDispoDAT
                    }
                    if ($json.VirtualizationSettings.RegistryDispositionLayers -AND ($script:versionNumber -ge 9.2)) {
                        # Back the DAT file
                        Backup-Dat $regDispoDAT
                        $OutputString = "`n"
                        $json.VirtualizationSettings.RegistryDispositionLayers.PSObject.Properties | ForEach-Object {
                            $location = $_.PSObject.Properties.Value.Location
                            if ($location -match " ") {
                                $location = "`"$location`""
                                $location = $location.Replace("\", "\\")
                            }
                            $OutputString += "$location`t`t $($_.PSObject.Properties.Value.Layer)`t`t $($_.PSObject.Properties.Value.Recurse)`n"
                        }
                        $OutputString = $OutputString -ireplace [regex]::Escape("True"), "TRUE"
                        $OutputString = $OutputString -ireplace [regex]::Escape("False"), "FALSE"
                        $OutputString | Out-String | Add-Content $regDispoDAT
                    }
                    break
                }
    "inputVal" {
                    if(!$ProjectName)
                    {
                        Throw 'Missing parameter: $ProjectName'
                    }
                    if(!$output_folder)
                    {
                        Throw 'Missing parameter: $output_folder'
                    }
                    if(!$installer_path)
                    {
                        Throw 'Missing parameter: $installer_path'
                    }
                    # Verify the installer can be found
                    if(-NOT (Test-Path -Path $installer_path))
                    {
                        Throw "Installer file does not exist: $installer_path"
                    }
                    # Verify the output path exists
                    if(-NOT (Test-Path -Path $output_folder))
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
IconFile=$IconFile

[CaptureSettings]
InstallerPath="$installer_path"
CommandLineParams="$CommandLineParams"
CaptureAllProcesses=$CaptureAllProcesses
CaptureTimeout=$CaptureTimeout
IgnoreChangesUnderInstallerPath=$IgnoreChangesUnderInstallerPath
ReplaceRegistryShortPaths=$ReplaceRegistryShortPaths
DefaultDispositionLayer=$DefaultDispositionLayer
DefaultServiceVirtualizationAction=$DefaultServiceVirtualizationAction

[PackagingSettings]
OutputFileNameNoExt=$OutputFileNameNoExt
OutputFolder="$output_folder"
FinalizeIntoSTP=$FinalizeIntoSTP
$AddFolderSection
$AddKeysSection
"@

# Execute the Cloudpaging-prep script, if present
if(Test-Path -Path $studioPrep)
{
#    & "$studioPrep" true
}

Write-Output "Starting to package $ProjectName automatically..."

# Create the input INI packaging file
if($processIni)
{
    $i = Split-Path $installer_path -Leaf
    $studioIni = $installer_path.Replace($i,"studio_config.ini")
    $script:createdFiles += $studioIni
    Write-Output "Creating non-interactive packaging INI as $studioIni"
    New-Item $studioIni -type file -force -value $functionText | Out-Null
} 
else 
{
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
    Restore-Dat($fileexcDAT)
    Restore-Dat($fileDispoDAT)
    Restore-Dat($regDispoDAT)
}
# Check if packaging was successful
if($process.ExitCode -eq 0)
{
    if($processIni)
    {
        $ProjectName = $ProjectName.Replace("`"","") #Ensure there are no extra quotes
        $appset = $output_folder + $ProjectName + ".stp"
        if($OutputFileNameNoExt){
            $OutputFileNameNoExt = $OutputFileNameNoExt.Replace("`"","")
            $appset = $output_folder + $OutputFileNameNoExt + ".stp"
        }
    }
    else
    {
        $IniLine = Get-Content -Path $studioIni | Where-Object { $_ -match 'OutputFolder=' }
        $appsetPath = $IniLine.Split('=')[1].Replace("`"","")
        $appset =  Get-ChildItem -Path $appsetPath -Filter *.stp -ErrorAction SilentlyContinue
        $appset = $appsetPath + $appset
    }
    # Verify output file exists
    if(-NOT (Test-Path -Path $appset))
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
                #Remove uneccessary files created during packaging
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
