########################################################################
#  Auto-Generate-and-Create-Package.ps1
#  Date: 2023-01-10
#  Author: Thomas Coulson
#
#  Description:
#  This script will auto run a json in NIP_software
#  Updated 2023-01-02:
#	Added most variablised options
#  Updated: 2023-02-07
#	Added custom file & Reg dispositions.
#	Added Reg modify and File Add params.
#  Updated: 2023-08-03
#	Added support for .cmd,.bat,.ps1
#
########################################################################


Param(
    [Parameter(Mandatory = $false)][ValidateScript({ $_.Replace("`"", '') -like '*.msi' -or $_.Replace("`"", '') -like '*.exe' -or $_.Replace("`"", '') -like '*.bat' -or $_.Replace("`"", '') -like '*.cmd' -or $_.Replace("`"", '') -like '*.ps1' -and (Test-Path -Path $_.Replace("`"", '') -PathType Leaf) -eq $true })]
    [string]$FilePath,
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
    [boolean]$FinalizeIntoSTP = $true,
    [Parameter(Mandatory = $false)]
    [boolean]$IncludeSourceDirectory = $false
)

#Set localmachine dir
$folder = 'C:\NIP_software'

if ($PSBoundParameters.Count -ge 1 -or $Args.Count -ge 1) {
    if (!$filepath) {
        Write-Error 'Please set a filepath to the msi/exe you wish to package' -ErrorAction stop
    }

    Write-Host "Copying install file $FilePath to $folder\auto\"
    Copy-Item -recurse "$FilePath" "$folder\auto" -force

    $installfiles = Get-ChildItem $folder\auto\ -Include $InstallFilename | Select-Object -ExpandProperty FullName

    if ($IncludeSourceDirectory -eq $true) {
        $SourceDirectory = Get-ChildItem $FilePath | Select-Object -ExpandProperty Directory
        Copy-Item -Path $SourceDirectory\* -Destination "$folder\auto\" -Recurse
    }
    Write-Host "Install file $installfiles found, creating Json."

    & "$folder\scripts\CreateJson.ps1" -FilePath $installfiles -Description $Description -Name $Name -IconFile $IconFile -WorkingFolder $WorkingFolder -Arguments $Arguments -StudioCommandline $StudioCommandline -outputfolder $outputfolder -Compression $Compression -Encryption $Encryption -CustomCommandlines $CustomCommandlines -RegistryExclusions $RegistryExclusions -FileExclusions $FileExclusions -ProcessesAllowedAccessToLayer4 $ProcessesAllowedAccessToLayer4 -ProcessesDeniedAccessToLayers3and4 $ProcessesDeniedAccessToLayers3and4 -CaptureAllProcesses $CaptureAllProcesses -IncludeSystemInstallationProcesses $IncludeSystemInstallationProcesses -IgnoreChangesUnderInstallerPath $IgnoreChangesUnderInstallerPath -ReplaceRegistryShortPaths $ReplaceRegistryShortPaths -IncludeChildProccesses $IncludeChildProccesses -Prerequisites $Prerequisites -PrerequisiteCommands $PrerequisiteCommands -DefaultServiceVirtualizationAction $DefaultServiceVirtualizationAction -FinalizeIntoSTP $FinalizeIntoSTP -Fileaddition $Fileaddition -Registrymodify $Registrymodify -CustomFileDisposition $CustomFileDisposition -CustomRegistryDisposition $CustomRegistryDisposition -CaptureTimeoutSec $CaptureTimeoutSec
}
else {
    $message = @"
Awaiting install file to be added to C:\NIP_software\Auto
If you would like to run a customised setup either add your json file with your install media to C:\NIP_software\Auto or run this script with the arguments you require e.g
C:\NIP_software\Auto-Generate-and-Create-Package.ps1 -FilePath `"\\myshare\mymsi.msi`" -Description `"Auto package of mymsi`" -Name `"MyMSI Cloudpaged`" -Arguments `"/qn /norestart TRANSFORMS=`"\\myshare\mymsi.mst`" -StudioCommandline `"C:\Program files\Myinstall\My.exe`"

"@
    Write-Host $message

    do {
        $filecheck = Test-Path "$folder\auto\*" -Include '*msi', '*.exe', '*sccmauto.ps1', '*.cmd', '*.ps1', '*.bat'
        $runningPS = Get-WmiObject Win32_Process -Filter "Name='powershell.exe' AND CommandLine LIKE '%Auto-Generate-and-Create-Package.ps1%'"

        If ($runningps.Count -gt 1) { exit }

    }until ($filecheck -eq $True)

    $installfiles = Get-ChildItem $folder\auto\ -Recurse -Include '*msi', '*.exe', '*sccmauto.ps1', '*.cmd', '*.ps1', '*.bat'
    if ($installfiles.Name -like '*sccmauto.ps1') {
        & $installfiles.FullName
    }

    $filecheckJson = Test-Path "$folder\auto\*" -Include '*.json'
    If ($filecheckJson -eq $true) {
        Write-Host 'Json file found, skipping Json Creation.'
        $Jsonfile = Get-ChildItem $folder\auto\ -Recurse -Include '*.json'

        if ($Jsonfile.basename -like '*sccmauto.json') {}
        elseif ($Jsonfile.basename -ne $installfiles.basename) {
            $ExpectedJsonName = $installfiles.basename + '.json'
            $CurrentJsonName = $Jsonfile.name
            Write-Host "Check Json name format. Expected name is $ExpectedJsonName, whereas current name is $CurrentJsonName. Please rename and run again"
            Start-Sleep 5
            exit
        }
    }
    else {
        Write-Host "Install file $installfiles found, creating Json."
        powershell -ep bypass -file "$folder\scripts\CreateJson.ps1" $installfiles.fullname
    }
}

Write-Host 'Json created, calling Cloudpaging NIP'
powershell -ep bypass -file "$folder\scripts\Auto_Install_from_json.ps1"
