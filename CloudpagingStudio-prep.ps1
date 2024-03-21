#   Cloudpaging Studio - System Prep
#
#   Copyright (c) 2019 Numecent, Inc.  All rights reserved.
#
#   This file is an unpublished work and the proprietary and confidential
#   information of Numecent.  Should this source code become published,
#   it is entitled to the fullest protection under the copyright laws,
#   as it was created as early as 1996, and continues to be updated and
#   owned by Numecent. Use, disclosure, reproduction, or distribution is
#   prohibited except as permitted by express written license agreement
#   with Numecent Inc.
#
# Revision Mar 21, 2024

# Pass in "true" to avoid prompting for confirmation
$confirm=$args[0]

# Requires Administrator Rights
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Warning "You do not have Administrator rights to run this script.`nPlease re-run this script as an Administrator."
    return
}

# Prompt for confirmation to run script
If ($confirm -ne "true")
{
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    $OUTPUT= [System.Windows.Forms.MessageBox]::Show("This script will disable the following services and scheduled tasks:`n`nMicrosoft Defender Cloud-delivered Protection`nWindows Search`nWindows Updates`nWindows Store App Updates`nWindows User Account Control (UAC)`nWindows System Restore`nWindows Superfetch Service`nChkdsk task`nDisk defrag task`nDisk cleanup tasks`n`nDo you wish to proceed?", "Confirmation" , 4) 
    if ($OUTPUT -eq "NO" ) 
    {
        return
    } 
}

function Disable-Service
{
    param([string]$ServiceName)

    # service status
    $ServiceInfo = Get-Service -Name $ServiceName

    If ($ServiceInfo.Status -eq ‘Running’) 
    {
        # set the service to "disabled"
        sc.exe config $ServiceName start=disabled | Out-Null

        # stop the service
        sc.exe stop $ServiceName | Out-Null
    } 
}

function Disable-Task
{
    param([string]$TaskName,
          [string]$TaskFolder,
          [string]$ComputerName = "localhost"
          )
    
    $TaskScheduler = New-Object -ComObject Schedule.Service
    $TaskScheduler.Connect($ComputerName)
    $TaskRootFolder = $TaskScheduler.GetFolder($TaskFolder)
    $Task = $TaskRootFolder.GetTask($TaskName)
    If (-Not $?)
    {
        Write-Error "Task $TaskName not found on $ComputerName"
        return
    }
    $Task.Enabled = $False
    Write-Host "  $TaskFolder\$TaskName disabled"
}


# Identify the Operating System
$OSName = (systeminfo | findstr /B /C:"OS Name").Substring(8).Trim()
$OSVersion = [Environment]::OSVersion.Version
$OSVersionDisplay = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name DisplayVersion).DisplayVersion
Write-Host "Disabling components on" $OSName $OSVersionDisplay `n

# Disable System Restore
Write-Host "Disabling Windows System Restore..."
Disable-ComputerRestore -Drive "C:\"

# Disable Microsoft Defender Cloud-delivered protection
Try
{
    $defenderOptions = Get-MpComputerStatus -ErrorAction Stop
    If (-NOT [string]::IsNullOrEmpty($defenderOptions))
    {
        Write-Host "Disabling Microsoft Defender Cloud-delivered protection..."
        Set-MpPreference -MAPSReporting Disabled
    }
}
Catch
{
    Write-Host "Microsoft Defender Cloud-delivered protection is NOT installed or Remotely Managed."
}

# Disable Windows Search
Write-Host "Disabling Windows Search..."
Disable-Service WSearch

# Disable Windows Updates
Write-Host "Disabling Windows Updates..."
Disable-Service wuauserv

# Disable Superfetch service
Write-Host "Disabling Windows Superfetch Service..."
Disable-Service SysMain

# Disable Microsoft Store updates
If ($OSVersion -ge (new-object 'Version' 6,2))
{
    Write-Host "Disabling Windows Store App Updates..."
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
    $Name = "AutoDownload"
    $value = "2"
    If (!(Test-Path $registryPath))
    {
    	New-Item -Path $registryPath -Force | Out-Null
    }
    New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
}
Else 
{
    Write-Host "Windows Store App NOT on legacy OSes."
}

# Disable Scheduled task - Chkdsk, Disk Defrag, Disk Cleanup
Write-Host "Disabling Scheduled tasks:"
If ($OSVersion -ge (new-object 'Version' 6,2))
{
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Chkdsk\ProactiveScan"
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Defrag\ScheduledDefrag"
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\DiskCleanup\SilentCleanup"
}
Else
{
    Disable-Task "ScheduledDefrag" "\Microsoft\Windows\Defrag"
    Disable-Task "MP Scheduled Scan" "\Microsoft\Windows Defender"
}

# Disable Windows user account control (UAC)
Write-Host "Disabling Windows User Account Control (UAC)..."
Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA -Type DWord -Value 0
Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableSecureUIAPaths -Type DWord -Value 0 
Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Type DWord -Value 0
Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorUser -Type DWord -Value 0
Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name PromptOnSecureDesktop -Type DWord -Value 0
Get-ChildItem -Path HKCU:\ -Recurse |
    Where-Object { $_.PSChildName  -eq "{C8E6F269-B90A-4053-A3BE-499AFCEC98C4}.check.0" } | 
    New-ItemProperty -Name CheckSetting -PropertyType Binary -Value (0x23,0x00,0x41,0x00,0x43,0x00,0x42,0x00,0x6C,0x00,0x6F,0x00,0x62,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00) -Force | Out-Null
Write-Host "You must restart your computer to turn off Windows User Account Control (UAC)."
