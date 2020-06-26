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
# Revision May 5, 2020

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
    The path to the executable installer which the user would like cloudpaging Studio to capture
.PARAMETER installer_url
    The download url for the installer which the user would like cloudpaging Studio to capture
.PARAMETER output_folder
    The folder where cloudpaging Studio will save the appset
.PARAMETER appset_name
    Name for the .stp appset not including extension
.PARAMETER offline
    When true, no network features will execute in this PowerShell script
.PARAMETER skip_verification
    When true, the SHA-256 hash value of the installer will not be checked against the json value
.PARAMETER debug_mode
    Assigning a non null value to this parameter prevents created files from being deleted

.EXAMPLE
    >studio-nip.ps1 -config_file_path 'c:\test\app.json'
    Will automatically package the application as specified in the app.json file

    >studio-nip.ps1 -config_file_path 'c:\test\app.json' -installer_path 'C:\test\installer.exe' -output_folder 'C:\test\Output'
    Will automatically package the installer.exe application as specified by the app.json file, and place the output files in the specified location
#>

param (
    [Parameter(Mandatory = $true, Position = 0)][string]$config_file_path,
    [Parameter(Mandatory = $false, Position = 1)][string]$installer_path = $null,
    [Parameter(Mandatory = $false, Position = 2)][string]$installer_url = $null,
    [Parameter(Mandatory = $false, Position = 3)][string]$output_folder = $null,
    [Parameter(Mandatory = $false, Position = 4)][string]$root_folder = $null,
    [Parameter(Mandatory = $false, Position = 5)][string]$appset_name = $null,
    [Parameter(Mandatory = $false, Position = 6)][string]$offline = $null,
    [Parameter(Mandatory = $false, Position = 7)][string]$skip_verification = $null,
    [Parameter(Mandatory = $false, Position = 8)][string]$debug_mode = $null
)

$NIPS_SCRIPT_VERSION = 1.0         #Version number for nips, this will be stored in revnotes
$SUPORTED_JSON = 1.0, 1.1         #Add supported version in array
$prescriptURL = "https://raw.githubusercontent.com/Numecent/Automated-Packaging/master/CloudpagingStudio-prep.ps1"
$datFilesDirectoryURL = "https://raw.githubusercontent.com/Numecent/Automated-Packaging/master/Studio%20DAT%20Files/"

$script:createdFiles = @()          #List of files created in automated packaging
$script:versionNumber = $null       #Cloudpaging Studio Version
$ErrorActionPreference = 'SilentlyContinue'
$rootDrive = Split-Path -Path $config_file_path -Qualifier                  #Check for alternative root drive
$ErrorActionPreference = 'Continue'
$studioPath = "$rootDrive\" + "Program Files\Numecent\Cloudpaging Studio\"  #CloudPaging Studio installation folder
if (-NOT (Test-Path -Path $studioPath)) {
    $studioPath = "C:\Program Files\Numecent\Cloudpaging Studio\"
}
$projectRoot = Split-Path $config_file_path -Parent
if($root_folder){
    $projectRoot = $root_folder
}
if($debug_mode){
    Write-Output "The root folder for the project is set to: $projectRoot"
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

$ProgressPreference = 'SilentlyContinue'
function Initialize-InstallWrapper {
    #Creates the .bat file that studio will track
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $installerLoaction
    )
    $default = '@ECHO OFF
SET SOURCE=%~dp0
SET SOURCE=%SOURCE:~0,-1%

'
    $batPath = $installerLoaction
    $installerName = Split-Path $batPath -Leaf
    $batPath = $batPath.Replace($installerName, "Installer.bat")

    $inst = "`"$installerLoaction`""
    $InstallCommand = "" + $json.CaptureCommands.InstallerPrefix + $inst + $json.CaptureCommands.InstallerCommands + "`n"

    $batString = $default + $installCommand + "`n"

    If ($json.CaptureCommands.PostInstallActions.Enabled) {
        $customString = $json.CaptureCommands.PostInstallActions.Commands | Out-String
        $batString = $batString + $customString
    }

    $batString | Out-String | Out-File -FilePath $batPath -Encoding ascii
    $script:createdFiles += $batPath

    return $batPath;
}

function Request-Installer {
    #Download installer from URL, create any folders needed
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $URL,
        [Parameter(Mandatory = $true, Position = 1)]
        [string] $downloadLoaction,
        [Parameter(Mandatory = $false, Position = 2)]
        [string] $fileName
    )

    if (-NOT (Test-Path -Path $downloadLoaction)) {
        try {
            $leaf = Split-Path -Path $downloadLoaction -Leaf
            if ($leaf.Contains(".")) {
                if (-NOT ($fileName)) {
                    $fileName = $leaf
                }
                $downloadLoaction = Split-Path $downloadLoaction -Parent
                if (-NOT($downloadLoaction.EndsWith('\'))) {
                    $downloadLoaction += "\"
                }
                if (-NOT (Test-Path -path $downloadLoaction)) {
                    mkdir $downloadLoaction | Out-Null
                }
            }
            else {
                if (-NOT($downloadLoaction.EndsWith('\'))) {
                    $downloadLoaction += "\"
                }
                mkdir $downloadLoaction | Out-Null
            }
        }
        catch {
            Throw "Error: Invalid path $downloadLoaction"
        }
    }
    try {
        $protocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
        [System.Net.ServicePointManager]::SecurityProtocol = $protocols
        (New-Object System.Net.WebClient).DownloadFile($url, ".\inst.tmp")
    }
    catch {
        Throw "Error: Web Request Failed"
    }
    try{
        if (-NOT ($fileName)) {
            $fileName = $url -split '/' | Select-Object -Last 1
        }
        $downloadLoaction += $fileName
        $downloadLoaction = $downloadLoaction.Replace('/', '')
        Move-Item .\inst.tmp $downloadLoaction
    }catch{
        Throw "Error: No file name found for $url, please provide one in the json file at DownloadPath"
    }

    return $downloadLoaction
}

function Get-ServiceString {
    #Get the tracked services information from the MERGE_RESULTS file
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $stwFolder,
        [Parameter(Mandatory = $true, Position = 1)]
        [string] $outputFolder
    )
    #Find file that contains MERGE_RESULTS
    #skip lines 0, 1, 2
    #Read lines until * is reached

    #$path = (get-item $StpFile).Directory.Parent.FullName
    $result = Get-ChildItem -Path $stwFolder -Recurse -Filter "*MERGE_RESULTS*"
    $mergeLogPath = $outputFolder + "/$result"

    $linect = 0
    $servicesString = ""

    foreach ($line in Get-Content $mergeLogPath) {
        $linect = $linect + 1

        if ($linect -le 3) {
            Continue #ignore header portion
        }
        elseif ($line -match "\*") {
            break #once next header is encountered end loop
        }
        $servicesString += "$line`n"

    }

    return $servicesString

}

function Format-RevNote {
    #Produce Revisions Notes file and store inside of the .stp appset
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $stpFile,
        [Parameter(Mandatory = $true, Position = 1)]
        [string] $stwFolder,
        [Parameter(Mandatory = $true, Position = 2)]
        [string] $installerName,
        [Parameter(Mandatory = $true, Position = 3)]
        [string] $outputFolder,
        [Parameter(Mandatory = $true, Position = 4)]
        $jsonObj
    )

    $date = Get-Date

    $services = Get-ServiceString $stwFolder $stwFolder
    $osString = ""
    foreach ($elem in $jsonObj.ProjectSettings.TargetOS) {
        $osString += $elem + ", "
    }
    $osString = $osString.TrimEnd(", ")


    $revNotesText = @"
# Numecent NIPS Revision Notes v1.0

NIPS_Script_Version = $NIPS_SCRIPT_VERSION
JSON_Version = $($jsonObj.JsonConfigVersion)
Studio_Version = $script:versionNumber
Date_Packaged = $date
Platform_Packaged_On = $osString
File_Name = $installerName
Compression = $($jsonObj.OutputSettings.CompressionMethod)
Encryption = $($jsonObj.OutputSettings.EncryptionMethod)

#|--------------------------------------------------------|
#|                  Services Captured                     |
#|--------------------------------------------------------|
$services
"@

    $zipName = Split-Path $stpFile -Leaf
    $zipName = $zipName.Replace(".stp", ".zip")

    Rename-Item -Path $StpFile -NewName $zipName
    $zipFile = $stpFile.Replace(".stp", ".zip")

    $notePath = $outputFolder + "\RevNotes.txt"

    $noteString = $revNotesText
    $noteString | Out-String | Out-File -FilePath $notePath

    $stpName = Split-Path $StpFile -Leaf

    Compress-Archive -Path $notePath -Update -DestinationPath $zipFile


    Rename-Item -Path $zipFile -NewName $stpName
    Remove-Item -Path $NotePath
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
    #Delete current dat file and restore file from .bak
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $datFile
    )

    If (Test-Path -Path $datFile".bak") {
        Copy-Item -Path $datFile".bak" -Destination $datFile -Force
        Remove-Item -Path $datFile".bak"
    }
}

function Initialize-RegData {
    #Create a .reg file to execute registry changes during capture
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $installerLoaction,
        [Parameter(Mandatory = $true, Position = 1)]
        $jsonObj
    )

    $installer = Split-Path $installerLoaction -Leaf

    $regFileCt = 0
    #ModifyKeys
    foreach ($entry in $jsonObj.ModifyAssets.ModifyKeys.PSObject.Properties.name) {
        if ($null -eq $jsonObj.ModifyAssets.AddFiles.PSObject.Properties.name) {
            break
        }

        $Location = $jsonObj.ModifyAssets.ModifyKeys.PSObject.Properties[$entry].value.PSObject.Properties["Location"].value
        $Keys = $jsonObj.ModifyAssets.ModifyKeys.PSObject.Properties[$entry].value.PSObject.Properties["Keys"].value

        $regString = "Windows Registry Editor Version 5.00`n`n"
        foreach ($line in $Keys) {
            $pos = $line.IndexOf("=")
            $one = $line.Substring(0, $pos)
            $two = $line.Substring($pos + 1)
            $regString += "[$Location]`n"
            $regString += "`"$one`"=$two`n`n"
        }

        if ($debug_mode) {
            Write-Output "Creating registry file:`n"
            Write-Output $regString
        }

        $name = "reg_changes$regFileCt.reg"
        $tempDestination = $installerLoaction.Replace($installer, $name)
        $regString | Out-File -FilePath $tempDestination -Encoding ascii
        $script:createdFiles += $tempDestination
        Add-Content $installerLoaction "regedit /s `"$tempDestination`"`n"
        $regFileCt++
    }
}

function Initialize-FileData {
    #Create files based off of json data, add instructions to move these during capture
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $installerLoaction,
        [Parameter(Mandatory = $true, Position = 1)]
        $jsonObj
    )

    $installer = Split-Path $installerLoaction -Leaf

    #AddFiles
    foreach ($entry in $jsonObj.ModifyAssets.AddFiles.PSObject.Properties.name) {
        if ($null -eq $jsonObj.ModifyAssets.AddFiles.PSObject.Properties.name) {
            Write-Output "No key modifications found"
            break
        }

        $name = $jsonObj.ModifyAssets.AddFiles.PSObject.Properties[$entry].value.PSObject.Properties["Name"].value
        $destination = $jsonObj.ModifyAssets.AddFiles.PSObject.Properties[$entry].value.PSObject.Properties["Destination"].value
        $content = $jsonObj.ModifyAssets.AddFiles.PSObject.Properties[$entry].value.PSObject.Properties["Content"].value | Out-String

        $tempDestination = $installerLoaction.Replace($installer, $name)
        if ($debug_mode) {
            Write-Output "Creating custom file: $name at $destination"
        }

        $content | Out-File -FilePath $tempDestination -Encoding ascii
        $script:createdFiles += $tempDestination

        #Add copy instructions to the Bat File
        Add-Content $installerLoaction "COPY `"$tempDestination`" `"$destination`" `n"
    }

}

function Invoke-PreCaptureScript {
    #Create a custom pre-capture script from json data
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $installerLoaction,
        [Parameter(Mandatory = $true, Position = 1)]
        $jsonObj
    )

    $installerName = Split-Path $installerLoaction -Leaf

    $scriptPath = $installerLoaction.Replace($installerName, "prescript.bat")
    $jsonObj.PreCaptureCommands | Out-String | Out-File -FilePath $ScriptPath -Encoding ascii


    $script = Start-Process -FilePath $scriptPath -Verb runas -Wait -PassThru
    $script:createdFiles += $scriptPath

    if ($script.ExitCode -eq 0) {
        return
    }
    else {
        Write-Output "WARNING: The pre capture instructions did not exit properly"
        $err = $script.ExitCode
        Write-Output "*$p Exit Code: $err*"
        return
    }
}

function Request-Script {
    #Download a script from url if it does not allready exist
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $prescript,
        [Parameter(Mandatory = $true, Position = 1)]
        [string] $URL,
        [Parameter(Mandatory = $true, Position = 2)]
        [string] $installerLocation
    )

    if (Test-Path -Path $prescript) {
        $inst = Split-Path $installerLocation -Leaf
        $temp = $installerLocation.Replace($inst , (Split-Path $prescript -Leaf))
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $URL -UseBasicParsing -OutFile $temp
        }
        catch {
            Write-Warning "Could not download newest prep script"
            return
        }
        $networkScript = Get-FileHash -path $temp | Select-Object Hash
        $localScript = Get-FileHash -path $prescript | Select-Object Hash
        if ($debug_mode) {
            Write-Output "Local script has hash value: $localScript"
            Write-Output "Network Script has hash value: $networkScript"
        }
        if ($networkScript.Hash -ne $localScript.Hash) {
            Write-Output "New prescript update found"
            Move-Item -Path $temp -Destination $prescript -Force
        }
        else {
            Remove-Item -Path $temp
            return
        }
    }
    else {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $URL -UseBasicParsing -OutFile $prescript
        }
        catch {
            Write-Warning "Could not download newest prep script"
            return
        }
    }
    return 'SUCCESS'
}

function Invoke-Script {
    #Create a bat file to execute a script as an admin and run it
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $path,
        [Parameter(Mandatory = $true, Position = 1)]
        [string] $command
    )

    $ext = (Split-Path -Path $path -Leaf).Split(".")[1];
    $executable = $path.Replace($ext, "bat")

    $command | Out-String | Out-File -FilePath $executable -Encoding ascii
    $script = Start-Process -FilePath $executable -Verb runas -Wait -PassThru
    $script:createdFiles += $executable

    if ($script.ExitCode -ne 0) {
        $err = $script.ExitCode
        Write-Warning "$path Did Not exit properly, Error: $err"
        return
    }

}
function Request-DatUpdate {
    #Download updates to dat files in studio lib folder
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $studioLocation,
        [Parameter(Mandatory = $true, Position = 1)]
        [string] $datURL
    )
    Get-ChildItem -Path "$studioLocation\lib" -Filter *.dat | ForEach-Object {
        $url = $datURL + $_.Name
        $location = $studioLocation + "lib\" + $_.Name
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $url -UseBasicParsing -OutFile $location
            Write-Output "Successfully updated $location"
        }
        catch {
            Write-Output "Did not find update: $location"
        }
    }
}

function Compare-Hash {
    #Compare hash value of downloaded file to value stored in json
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $jsonHash,
        [Parameter(Mandatory = $true, Position = 1)]
        [string] $fileHash
    )
    if (-NOT ($jsonHash)) {
        Write-Warning "No SHA-256 found, use `"-skip_verification 'true'`" parameter to bypass verification"
        throw "Error: Verification could not be completed"
    }

    if (-NOT ($jsonHash -match $fileHash)) {
        Write-Warning "Downloaded Installer SHA-256: $fileHash"
        Write-Warning "JSON Installer SHA-256: $jsonHash"
        Throw "Error: SHA-256 Mismatch"
    }
}

function Get-Path {
    #Obtain the correct path and create it if necessary from parameter/ json information
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $projectRoot,
        [Parameter(Mandatory = $true, Position = 1)]
        [string] $jsonPath,
        [Parameter(Mandatory = $false, Position = 2)]
        [string] $parameterVal = $null
    )
    $path = ""
    $file = ""
    if($parameterVal){
        $jsonPath = $parameterVal
    }
    if(-NOT ($jsonPath) ){
        return
    }
    if(-NOT ($jsonPath.replace('\','') -match $projectRoot.replace('\','')) ){
        #IF the provided path is not a full path
        if ($jsonPath -match '%SOURCE%\\'){
            $jsonPath = $jsonPath.replace('%SOURCE%', 'Installer_Cfg')
        }
        $ErrorActionPreference = 'SilentlyContinue'
        $drive = Split-Path -Path $jsonPath -Qualifier
        $ErrorActionPreference = 'Continue'
        if ($drive) {
            $jsonPath = $jsonPath.replace("$drive\", '')
        }
        $path = $projectRoot + '\' + $jsonPath
    }
    else{
        $path = $jsonPath
    }
    #If this is a path for an installer, remove the leaf from the path so mkdir can be called
    $leaf = Split-Path -Path $path -Leaf
    if ($leaf.Contains(".")) {
            $file = $leaf
            $path = $path.Replace($file, '')
    }
    if($path[0] -eq '\'){
        $path = $path.Substring(0,2) + $path.substring(2).Replace('\\','\')
    }else{
        $path = $path.Replace('\\','\')
    }

    if (-NOT (Test-Path -path $path)) {
        mkdir $path | Out-Null
    }
    return ($path + $file)

}

# Requires Administrator Rights
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Throw "You do not have Administrator rights to run this script.`nPlease re-run this script as an Administrator."
}

# Verify Studio is installed and UAC is disabled
if (-NOT (Test-Path -Path $studioCmd)) {
    Throw "Cloudpaging Studio was not found to be installed at location: $studioPath"
}
if ((Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).EnableLUA) {
    Throw "Windows user access control (UAC) is enabled on this machine and can interfere with automated packaging."
}

$script:versionNumber = [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$studioPath/JukeboxStudio.exe").FileVersion
Write-Output "Cloudpaging Studio Version: $script:versionNumber"
# Verify the parameter


if (!$config_file_path) {
    Throw 'Missing parameter: $config_file_path'
}

# Verify the JSON file can be found
if (-NOT (Test-Path -Path $config_file_path)) {
    Throw "JSON file does not exist: $config_file_path"
}

#$studioIni = $config_file_path
$studioLog = "$([io.path]::getdirectoryname($config_file_path))\" + "$([io.path]::GetFileNameWithoutExtension($config_file_path))_NIP.log"
# Read the INI for a project name
############################################
#               Verify JSON                #
############################################
$json = Get-Content $config_file_path | ConvertFrom-Json

[double]$version = $json.JsonConfigVersion -as [double]

#Make sure Json is supported version
if ($SUPORTED_JSON.Contains($version)) {
    Write-Output "Reading config file version: $($json.JsonConfigVersion)"
}
else {
    $min = $SUPORTED_JSON | Measure-Object -Minimum
    if ($min -gt $version) {
        Write-Warning "This configuration file is no longer supported, would you like to continue anyways?"
    }
    else {
        Write-Warning "This configuration file request a newer version of NIPS, would you like to continue anyways?"
    }

    Write-Output "Press `"Enter`" to continue or `"Ctrl-C`" to cancel"
    do {
        $key = [Console]::ReadKey("noecho")
    }while ($key.Key -ne "Enter")
}

#Make sure installer is present, or can be downloaded and verified
if (-NOT $installer_path) {
    $installer_path = $json.CaptureCommands.InstallerPath
}
if (-NOT $installer_url) {
    $installer_url = $json.InstallerDownload.DownloadURL
}
if (-NOT (Test-Path -Path $installer_path)) {
    #If there is a local file with the same extension at the path, attempt to use that file (Assume mistyped name)
    $folder = Split-Path $installer_path -Parent
    $ext = "*." + (Split-Path -Path $installer_path -Leaf).Split(".")[1];
    $foundAlt = $False
    if (Test-Path -Path $folder) {
        if ((Get-ChildItem -Path $folder -Filter $ext) -and (-NOT ($installer_url))) {
            $installer_path = Get-ChildItem -Path $folder -Filter $ext | select-object -First 1
            Write-Output "Could not find exact installer, but found executable: $installer_path at location instead. Attempting to package...."
            $installer_path = $folder + "\" + $installer_path
            Write-Output $installer_path
            $foundAlt = $True
        }
    }
    if ($installer_url -and !$foundAlt) {
        #Download Installer
        if ($json.InstallerDownload.DownloadPath) {
            $installer_path = Get-Path -projectRoot $projectRoot -jsonPath $json.InstallerDownload.DownloadPath
        }
        Write-Output "Downloading installer, this may take a moment..."
        $start_time = New-Object System.Diagnostics.Stopwatch
        $start_time.Start()
        $installer_path = Request-Installer -URL $installer_url $installer_path
        $start_time.Stop()
        if($debug_mode){
            $d = $start_time.ElapsedMilliseconds
            Write-Output "Completed download in $d miliseconds"
        }
        Write-Output "Downloaded installer to: $installer_path"
        if (-NOT ($skip_verification)) {
            #Compare hash value of downloaded file to value stored in json
            $h = Get-FileHash -path $installer_path -Algorithm SHA256 | Select-Object Hash
            $h2 = $json.InstallerDownload.'SHA-256'
            try {
                Compare-Hash -jsonHash $h2 -fileHash $h.Hash
            }
            catch {
                throw "Error: Verification could not be completed"
            }
        }
    }
    else {
        throw "Error: No installer could be found, please update installer path or provide a download URL"
    }
}

$output_folder = Get-Path -projectRoot $projectRoot -jsonPath $json.OutputSettings.OutputFolder -parameterVal $output_folder
if(!$output_folder){
    Throw "Please provide an output folder in the config file or with the -output_folder parameter"
}
if(-NOT ($path -match '\\$')){
         $output_folder = $output_folder + '\'
 }

$WorkingFolder = ""
if (!$working_folder) {
    if ($json.ProjectSettings.WorkingFolder) {
        $WorkingFolder = $json.ProjectSettings.WorkingFolder #Old version
    }
    elseif ($json.ProjectSettings.TargetCommand.WorkingFolder) {
        $WorkingFolder = $json.ProjectSettings.TargetCommand.WorkingFolder #New version
    }
    else {
        #No working folder provided
    }
}

############################################
#               Process JSON               #
############################################
$fileName = Split-Path $installer_path -Leaf
####set required settings here###
#   '#' = Not currently being communicated to cloudpaging studio
$ProjectName = $json.ProjectSettings.ProjectName
$ProjectDescription = $json.ProjectSettings.ProjectDescription
$CompressionMethod = $json.OutputSettings.CompressionMethod
$EncryptionMethod = $json.OutputSettings.EncryptionMethod
$CommandLine = $json.ProjectSettings.TargetCommand.CommandLine
$CommandLineParams = $json.ProjectSettings.CommandLineParams
$CaptureTimeout = $json.CaptureSettings.CaptureTimeoutSec
$DefaultDispositionLayer = $json.VirtualizationSettings.DefaultDispositionLayer
$OutputFileNameNoExt = $json.OutputSettings.OutputFileNameNoExt
$IconFile = $json.ProjectSettings.ProjectIconFile
$ProjectFolder = ""
if($json.ProjectSettings.ProjectFolder){
    $ProjectFolder = Get-Path -projectRoot $projectRoot -jsonPath $json.ProjectSettings.ProjectFolder
}
if(-NOT ($ProjectFolder)){
    $ProjectFolder = $output_folder
}
if ($json.ProjectSettings.IconFile) {
    $IconFile = $json.ProjectSettings.IconFile
}
if ($json.ProjectSettings.CommandLine) {
    $CommandLine = $json.ProjectSettings.CommandLine
}
#$ProjectFileName = $json.ProjectSettings.ProjectFileName
#$IgnoreChangesUnderInstallerPath = $json.CaptureSettings.IgnoreChangesUnderInstallerPath
#$ReplaceRegistryShortPaths = $json.CaptureSettings.ReplaceRegistryShortPaths

#Convert boolean values into strings for studio ini
$CaptureAllProcesses = "No"
if ($json.CaptureSettings.CaptureAllProcesses) {
    $CaptureAllProcesses = "Yes"
}
$FinalizeIntoSTP = "Yes"
if (!$json.OutputSettings.FinalizeIntoSTP) {
    $FinalizeIntoSTP = "No"
}
if ($appset_name) {
    #Overrite $OutputFileNameNoExt with parameter if provided
    $OutputFileNameNoExt = $appset_name
}
if ($OutputFileNameNoExt -match " ") {
    $OutputFileNameNoExt = "`"$OutputFileNameNoExt`""
}
#If indicated, download pre-reqs
if ($json.CaptureCommands.PrerequisiteDownload) {
    $json.CaptureCommands.PrerequisiteDownload.PSObject.Properties | ForEach-Object {
        $prereq = Request-Installer -URL $_.PSObject.Properties.Value.DownloadURL -downloadLoaction $_.PSObject.Properties.Value.DownloadPath
        Write-Output "Downloaded pre-req: $prereq"
        if (-NOT ($skip_verification)) {
            $prereqHash = Get-FileHash -path $prereq -Algorithm SHA256 | Select-Object Hash
            $jsonHash = $_.PSObject.Properties.Value.'SHA-256'
            Compare-Hash -jsonHash $jsonHash -fileHash $prereqHash.hash
        }
    }
}
#if indicated, create a bat file
if ($json.CaptureCommands.Enabled) {
    $installer_path = Initialize-InstallWrapper $installer_path
    Write-Output "Installer path is $installer_path"
}
#if indicated, create a .reg file
if ($null -ne $json.ModifyAssets.ModifyKeys.PSObject.Properties.name) {
    if ($debug_mode) {
        Write-Output "Initilizing Registry Data...."
    }
    Initialize-RegData $installer_path $json
}
#if indicated, create additional files
if ($null -ne $json.ModifyAssets.AddFiles.PSObject.Properties.name) {
    if ($debug_mode) {
        Write-Output "Initilizing File Data...."
    }
    Initialize-FileData $installer_path $json
}
#Check for updates to studio prep script and dat files
if (-NOT $offline) {
    if ((Request-Script -prescript $studioPrep -URL $prescriptURL -installerLocation $installer_path) -match "SUCCESS") {
        $command = "powershell.exe `"& '$studioPrep'`" true"
        Invoke-Script -path $studioPrep -command $command
    }
    Request-DatUpdate $studioPath $datFilesDirectoryURL
}
#Execute pre capture commands from json
if ($json.PreCaptureCommands) {
    if ($debug_mode) {
        Write-Output "Creating pre-capture script..."
    }
    Invoke-PreCaptureScript $installer_path $json
}

############################################
#            Update Dat Layers             #
############################################

if ($json.CaptureSettings.FileExclusions) {
    # Back the DAT file
    Backup-Dat $fileDAT
    # Append DAT files
    Add-Content $fileDAT "`r`n`n# -------------------------"
    Add-Content $fileDAT "`n# Filters for $ProjectName`n"
    #Create Output String and format for writing to DAT file

    $OutputString = ""
    $Name = "NIPS_FILE_EX"
    $index = 1
    foreach ($entry in $json.CaptureSettings.FileExclusions) {
        $entry = $entry.Trim()
        $n = $Name + $index
        $index++
        $OutputString += $n + "`t`t" + $entry + "`n"
    }

    $OutputString | Out-String | Add-Content $fileDAT
}

# Find DAT registry filter updates
if ($json.CaptureSettings.RegistryExclusions) {
    # Back the DAT file
    Backup-Dat $regDAT
    # Append DAT files
    Add-Content $regDAT "`r`n`n# -------------------------`n# Filters for $ProjectName`n"
    #Create Output String and format for writing to DAT file
    $OutputString = ""
    $Name = "NIPS_REG_EX"
    $index = 1
    foreach ($entry in $json.CaptureSettings.RegistryExclusions) {
        $n = $Name + $index
        $index++
        $entry = $entry.Trim()

        if ($entry -match " ") {
            $OutputString += $n + "`t" + "`"$($entry)`"`n"
        }
        else {
            $OutputString += $n + "`t" + $entry + "`n"
        }
    }
    $OutputString | Out-String | Add-Content $regDAT
}

# Find DAT process exclusion filter updates
if ($json.CaptureSettings.ProcessExclusions) {
    # Back the DAT file
    Backup-Dat $procexDAT
    # Append DAT files
    Add-Content $procexDAT "`r`n`n# -------------------------`n# Filters for $ProjectName`n"
    #Create Output String and format for writing to DAT file
    $OutputString = ""
    foreach ($entry in $json.CaptureSettings.ProcessExclusions) {
        if ($entry -match " ") {
            $OutputString += "`"$($entry)`"`n"
        }
        else {
            $OutputString += $entry + "`n"
        }
    }
    $OutputString | Out-String | Add-Content $procexDAT
}

# Find DAT process filter updates
if ($json.CaptureSettings.ProcessInclusions.Include) {
    # Back the DAT file
    Backup-Dat $procfiltDAT
    # Append DAT files
    Add-Content $procfiltDAT "`n# Filters for $ProjectName"
    #Create Output String and format for writing to DAT file
    $OutputString = ""
    $bool = "TRUE"
    if (-NOT ($json.CaptureSettings.ProcessInclusions.IncludeChildProccesses)) {
        $bool = "FALSE"
    }

    foreach ($entry in $json.CaptureSettings.ProcessInclusions.Include) {

        if ($entry -match " ") {
            $OutputString += "`"$($entry)`"`t`t" + $bool + "`n"
        }
        else {
            $OutputString += $entry + "`t`t" + $bool + "`n"
        }
    }

    $OutputString | Out-String | Add-Content $procfiltDAT
}
# Find DAT process filter updates
if ($json.SecurityOverrideSettings.AllowAccessLayer4.Proccesses -Or $json.SecurityOverrideSettings.DenyAccessLayer3) {
    # Back the DAT file
    Backup-Dat $defprocsDAT
    #Check if DAT entry needs update
    $file_text = Get-Content $defprocsDAT
    $json.SecurityOverrideSettings.PSObject.Properties.Name | ForEach-Object {
        $wordSearch = $_; #current key in loop
        $containsWord = $file_text | ForEach-Object { $_ -match $wordSearch } #if we match that key

        if ($containsWord -contains $true) {
            #comments out key
            ($file_text) | ForEach-Object { $_ -replace $wordSearch, "# $wordSearch" } | Set-Content $defprocsDAT
        }
    }

    # Append DAT files
    Add-Content $defprocsDAT "`r`n`n# -------------------------"
    Add-Content $defprocsDAT "`n# Settings for $ProjectName`n"
    #Create Output String and format for writing to DAT file
    $OutputString = ""
    $bool = "TRUE"
    if (-NOT ($json.SecurityOverrideSettings.AllowAccessLayer4.AllowReadAndCopy)) {
        $bool = "FALSE"
    }

    foreach ($proc in $json.SecurityOverrideSettings.AllowAccessLayer4.Proccesses) {
        $OutputString += "$proc`t`tTRUE`t$bool`n"
    }
    foreach ($proc in $json.SecurityOverrideSettings.DenyAccessLayer3) {
        $OutputString += "$proc`t`tFALSE`n"
    }

    $OutputString | Out-String | Add-Content $defprocsDAT
}
if ($json.VirtualizationSettings.SandboxFileExclusions) {
    # Back the DAT file
    Backup-Dat $fileexcDAT
    # Append DAT files
    Add-Content $fileexcDAT "`r`n`n# -------------------------"
    Add-Content $fileexcDAT "`n# Settings for $ProjectName`n"
    #Create the String and format for writing to DAT file
    $OutputString = $json.VirtualizationSettings.SandboxFileExclusions | Out-String
    $OutputString | Out-String | Add-Content $fileexcDAT
}
if ($json.VirtualizationSettings.SandboxRegistryExclusions) {
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
    $OutputString = ""
    $json.VirtualizationSettings.FileDispositionLayers.PSObject.Properties | ForEach-Object {
        $path = $_.PSObject.Properties.Value.Path
        if ($path -match " ") {
            $path = "`"$path`""
            $path = $path.Replace("\", "\\")
        }
        $OutputString += "$path`t`t $($_.PSObject.Properties.Value.Layer)`t`t $($_.PSObject.Properties.Value.Recurse)`n"
    }
    $OutputString = $OutputString.Replace("True", "TRUE")
    $OutputString = $OutputString.Replace("False", "FALSE")
    $OutputString | Out-String | Add-Content $fileDispoDAT
}
if ($json.VirtualizationSettings.RegistryDispositionLayers -AND ($script:versionNumber -ge 9.2)) {
    # Back the DAT file
    Backup-Dat $regDispoDAT
    $OutputString = ""
    $json.VirtualizationSettings.RegistryDispositionLayers.PSObject.Properties | ForEach-Object {
        $location = $_.PSObject.Properties.Value.Location
        if ($location -match " ") {
            $location = "`"$location`""
            $location = $location.Replace("\", "\\")
        }
        $OutputString += "$location`t`t $($_.PSObject.Properties.Value.Layer)`t`t $($_.PSObject.Properties.Value.Recurse)`n"
    }
    $OutputString = $OutputString.Replace("True", "TRUE")
    $OutputString = $OutputString.Replace("False", "FALSE")
    $OutputString | Out-String | Add-Content $regDispoDAT
}

# Define the input INI packaging file
$functionText = @"
[ProjectSettings]
ProjectName="$ProjectName"
ProjectDescription="$ProjectDescription"
ProjectFolder="$ProjectFolder"
TargetOS=$TargetOS
CompressionMethod=$CompressionMethod
EncryptionMethod=$EncryptionMethod
CommandLine="$CommandLine"
WorkingFolder="$WorkingFolder"
IconFile="$IconFile"

[CaptureSettings]
InstallerPath="$installer_path"
CommandLineParams="$CommandLineParams"
CaptureAllProcesses=$CaptureAllProcesses
CaptureTimeout=$CaptureTimeout
DefaultDispositionLayer=$DefaultDispositionLayer
DefaultServiceVirtualizationAction=$DefaultServiceVirtualizationAction

[PackagingSettings]
OutputFileNameNoExt=$OutputFileNameNoExt
OutputFolder="$output_folder"
FinalizeIntoSTP=$FinalizeIntoSTP
"@

Write-Output "Starting to package $ProjectName automatically..."

# Create the input INI packaging file

$i = Split-Path $installer_path -Leaf
$studioIni = $installer_path.Replace($i, "studio_config.ini")
$script:createdFiles += $studioIni
Write-Output "Creating non-interactive packaging INI as $studioIni"
New-Item $studioIni -type file -force -value $functionText | Out-Null


Write-Output "Output log file is $studioLog "

# Call Studio to package non-interactively
Write-Output "Starting Studio for non-interactive packaging..."
$process = Start-Process -FilePath $studioCmd -ArgumentList "-a ""$studioIni""  -l ""$studioLog"" " -Verb runas -Wait -PassThru

# Reverse changes to DAT files
if (-NOT ($debug_mode)) {
    Restore-Dat($fileDAT)
    Restore-Dat($regDAT)
    Restore-Dat($defprocsDAT)
    Restore-Dat($regexDAT)
    Restore-Dat($procexDAT)
    Restore-Dat($procfiltDAT)
    Restore-Dat($procfiltDAT)
    Restore-Dat($fileexcDAT)
    Restore-Dat($fileDispoDAT)
    Restore-Dat($regDispoDAT)
}
# Check if packaging was successful
if ($process.ExitCode -eq 0) {
    $ProjectName = $ProjectName.Replace("`"", "") #Ensure there are no extra quotes
    $appset = $output_folder + $ProjectName + ".stp"
    if ($OutputFileNameNoExt) {
        $OutputFileNameNoExt = $OutputFileNameNoExt.Replace("`"", "")
        $appset = $output_folder + $OutputFileNameNoExt + ".stp"
    }
    if (-NOT (Test-Path -Path $appset)) {
        Write-Warning "Application package was not found: $appset"
        return
    }
    else {
        $appsetSize = ((Get-Item $appset).length / 1GB)
        if ($appsetSize -lt 4) {
            Format-RevNote -stpFile $appset -stwFolder $projectFolder -installerName $fileName -outputFolder $output_folder -jsonObj $json
        }

        Write-Output "Completed packaging successfully..."
        Write-Output "Package can be found at: $appset"

        if (-NOT ($debug_mode)) {
            foreach ($file in $script:createdFiles) {
                #Remove uneccessary files created during packaging
                Remove-Item -Path $file
            }
        }
    }
}
else {
    $packageError = "Error packaging: 0x" + [Convert]::ToString($process.ExitCode, 16)
    Write-Warning -Message $packageError
    switch ([Convert]::ToString($process.ExitCode, 16)) {
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
        default { Write-Warning "An unspecified error occurred" }
    }
    Write-Warning "Please see output log for details"
    Throw $process.ExitCode
}

return
