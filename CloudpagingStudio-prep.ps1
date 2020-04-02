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
# Revision Jan 15, 2019

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
    $OUTPUT= [System.Windows.Forms.MessageBox]::Show("This script will disable the following services and scheduled tasks:`n`nDefender real-time monitoring`nWindows search`nWindows updates`nWindows Store updates`nSystem restore`nSuper fetch`nChkdsk task`nDisk defrag task`nDisk cleanup tasks`n`nDo you wish to proceed?", "Confirmation" , 4) 
    if ($OUTPUT -eq "NO" ) 
    {
        return
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
$OSName = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName
$OSVersion = [Environment]::OSVersion.Version
Write-Host "Disabling components on" $OSName $OSVersion `n

# Disable System Restore
Write-Host "Disabling System Restore..."
Disable-ComputerRestore -Drive "C:\"

# Disable Microsoft Defender
Try
{
    $defenderOptions = Get-MpComputerStatus -ErrorAction Stop
    If (-NOT [string]::IsNullOrEmpty($defenderOptions))
    {
        Write-Host "Disabling Microsoft Defender..."
        Set-MpPreference -DisableRealtimeMonitoring $true
    }
}
Catch
{
    Write-Host "Microsoft Defender is NOT installed or Remotely Managed."
}

# Disable Windows Search
Write-Host "Disabling Windows Search..."
Set-Service WSearch -StartupType Disabled
Stop-Service WSearch

# Disable Windows Updates
Write-Host "Disabling Windows Updates..."
Set-Service wuauserv -StartupType Disabled
Stop-Service wuauserv

# Disable Superfetch service
Write-Host "Disabling Superfetch Service..."
Set-Service SysMain -StartupType Disabled
Stop-Service SysMain

# Disable AppX Deployment service
If ($OSVersion -ge (new-object 'Version' 6,2))
{
    Write-Host "Stopping AppX Deployment Service..."
    Stop-Service AppXSVC
}
Else 
{
    Write-Host "AppX Deployment Service NOT on legacy OSes."
}

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

# SIG # Begin signature block
# MIIZTgYJKoZIhvcNAQcCoIIZPzCCGTsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUOvVpWvqYC+/JORPtEOmdgb5I
# 73agghRdMIID7jCCA1egAwIBAgIQfpPr+3zGTlnqS5p31Ab8OzANBgkqhkiG9w0B
# AQUFADCBizELMAkGA1UEBhMCWkExFTATBgNVBAgTDFdlc3Rlcm4gQ2FwZTEUMBIG
# A1UEBxMLRHVyYmFudmlsbGUxDzANBgNVBAoTBlRoYXd0ZTEdMBsGA1UECxMUVGhh
# d3RlIENlcnRpZmljYXRpb24xHzAdBgNVBAMTFlRoYXd0ZSBUaW1lc3RhbXBpbmcg
# Q0EwHhcNMTIxMjIxMDAwMDAwWhcNMjAxMjMwMjM1OTU5WjBeMQswCQYDVQQGEwJV
# UzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xMDAuBgNVBAMTJ1N5bWFu
# dGVjIFRpbWUgU3RhbXBpbmcgU2VydmljZXMgQ0EgLSBHMjCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBALGss0lUS5ccEgrYJXmRIlcqb9y4JsRDc2vCvy5Q
# WvsUwnaOQwElQ7Sh4kX06Ld7w3TMIte0lAAC903tv7S3RCRrzV9FO9FEzkMScxeC
# i2m0K8uZHqxyGyZNcR+xMd37UWECU6aq9UksBXhFpS+JzueZ5/6M4lc/PcaS3Er4
# ezPkeQr78HWIQZz/xQNRmarXbJ+TaYdlKYOFwmAUxMjJOxTawIHwHw103pIiq8r3
# +3R8J+b3Sht/p8OeLa6K6qbmqicWfWH3mHERvOJQoUvlXfrlDqcsn6plINPYlujI
# fKVOSET/GeJEB5IL12iEgF1qeGRFzWBGflTBE3zFefHJwXECAwEAAaOB+jCB9zAd
# BgNVHQ4EFgQUX5r1blzMzHSa1N197z/b7EyALt0wMgYIKwYBBQUHAQEEJjAkMCIG
# CCsGAQUFBzABhhZodHRwOi8vb2NzcC50aGF3dGUuY29tMBIGA1UdEwEB/wQIMAYB
# Af8CAQAwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NybC50aGF3dGUuY29tL1Ro
# YXd0ZVRpbWVzdGFtcGluZ0NBLmNybDATBgNVHSUEDDAKBggrBgEFBQcDCDAOBgNV
# HQ8BAf8EBAMCAQYwKAYDVR0RBCEwH6QdMBsxGTAXBgNVBAMTEFRpbWVTdGFtcC0y
# MDQ4LTEwDQYJKoZIhvcNAQEFBQADgYEAAwmbj3nvf1kwqu9otfrjCR27T4IGXTdf
# plKfFo3qHJIJRG71betYfDDo+WmNI3MLEm9Hqa45EfgqsZuwGsOO61mWAK3ODE2y
# 0DGmCFwqevzieh1XTKhlGOl5QGIllm7HxzdqgyEIjkHq3dlXPx13SYcqFgZepjhq
# IhKjURmDfrYwggSjMIIDi6ADAgECAhAOz/Q4yP6/NW4E2GqYGxpQMA0GCSqGSIb3
# DQEBBQUAMF4xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3Jh
# dGlvbjEwMC4GA1UEAxMnU3ltYW50ZWMgVGltZSBTdGFtcGluZyBTZXJ2aWNlcyBD
# QSAtIEcyMB4XDTEyMTAxODAwMDAwMFoXDTIwMTIyOTIzNTk1OVowYjELMAkGA1UE
# BhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMTQwMgYDVQQDEytT
# eW1hbnRlYyBUaW1lIFN0YW1waW5nIFNlcnZpY2VzIFNpZ25lciAtIEc0MIIBIjAN
# BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAomMLOUS4uyOnREm7Dv+h8GEKU5Ow
# mNutLA9KxW7/hjxTVQ8VzgQ/K/2plpbZvmF5C1vJTIZ25eBDSyKV7sIrQ8Gf2Gi0
# jkBP7oU4uRHFI/JkWPAVMm9OV6GuiKQC1yoezUvh3WPVF4kyW7BemVqonShQDhfu
# ltthO0VRHc8SVguSR/yrrvZmPUescHLnkudfzRC5xINklBm9JYDh6NIipdC6Anqh
# d5NbZcPuF3S8QYYq3AhMjJKMkS2ed0QfaNaodHfbDlsyi1aLM73ZY8hJnTrFxeoz
# C9Lxoxv0i77Zs1eLO94Ep3oisiSuLsdwxb5OgyYI+wu9qU+ZCOEQKHKqzQIDAQAB
# o4IBVzCCAVMwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAO
# BgNVHQ8BAf8EBAMCB4AwcwYIKwYBBQUHAQEEZzBlMCoGCCsGAQUFBzABhh5odHRw
# Oi8vdHMtb2NzcC53cy5zeW1hbnRlYy5jb20wNwYIKwYBBQUHMAKGK2h0dHA6Ly90
# cy1haWEud3Muc3ltYW50ZWMuY29tL3Rzcy1jYS1nMi5jZXIwPAYDVR0fBDUwMzAx
# oC+gLYYraHR0cDovL3RzLWNybC53cy5zeW1hbnRlYy5jb20vdHNzLWNhLWcyLmNy
# bDAoBgNVHREEITAfpB0wGzEZMBcGA1UEAxMQVGltZVN0YW1wLTIwNDgtMjAdBgNV
# HQ4EFgQURsZpow5KFB7VTNpSYxc/Xja8DeYwHwYDVR0jBBgwFoAUX5r1blzMzHSa
# 1N197z/b7EyALt0wDQYJKoZIhvcNAQEFBQADggEBAHg7tJEqAEzwj2IwN3ijhCcH
# bxiy3iXcoNSUA6qGTiWfmkADHN3O43nLIWgG2rYytG2/9CwmYzPkSWRtDebDZw73
# BaQ1bHyJFsbpst+y6d0gxnEPzZV03LZc3r03H0N45ni1zSgEIKOq8UvEiCmRDoDR
# EfzdXHZuT14ORUZBbg2w6jiasTraCXEQ/Bx5tIB7rGn0/Zy2DBYr8X9bCT2bW+IW
# yhOBbQAuOA2oKY8s4bL0WqkBrxWcLC9JG9siu8P+eJRRw4axgohd8D20UaF5Mysu
# e7ncIAkTcetqGVvP6KUwVyyJST+5z3/Jvz4iaGNTmr1pdKzFHTx/kuDDvBzYBHUw
# ggUZMIIEAaADAgECAhAFXHiCBIbnyVa0P26SLj68MA0GCSqGSIb3DQEBBQUAMG8x
# CzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3
# dy5kaWdpY2VydC5jb20xLjAsBgNVBAMTJURpZ2lDZXJ0IEFzc3VyZWQgSUQgQ29k
# ZSBTaWduaW5nIENBLTEwHhcNMTkxMDEwMDAwMDAwWhcNMjIxMTA5MTIwMDAwWjBl
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEPMA0GA1UEBxMGSXJ2
# aW5lMRcwFQYDVQQKEw5OdW1lY2VudCwgSW5jLjEXMBUGA1UEAxMOTnVtZWNlbnQs
# IEluYy4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCy2i+Rd01MgQEt
# ZUomvD3c1N5HZFT4RJjx+2oWAKo9CCt1hfZYvPV1FKb24WBqj/rPq3LvWBeYayfn
# INwaf2ZhvKj/RDSiOeigPvMHKZgMYxxDldPJ1coRjsrvdwI5OOCg6KRKmME0aJvc
# 2Q1HXtxIOAqhaaNueb68gWKzCu0alXWdxfOKuG8Sl4AyK9mfr58eFnm7aLxbHRs+
# pIwyLSFL3eTl9oA4KsQXJjSn/n2WZYxoqOfZK+Tc32XWBhhqfk1x7/pE+GSixyt2
# AcmiOCEY1TYaOPXr15bPzegiEV6NZz5n+hRhRRzL9pj0y2dfdvpt2jQU5y+CXO+M
# rv38Er+JAgMBAAGjggG5MIIBtTAfBgNVHSMEGDAWgBR7aM4pqsAXvkl64eU/1qf3
# RY81MjAdBgNVHQ4EFgQUTUbMSmiQPYLOTnYXo8V8dyqT0nUwDgYDVR0PAQH/BAQD
# AgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMG0GA1UdHwRmMGQwMKAuoCyGKmh0dHA6
# Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9hc3N1cmVkLWNzLWcxLmNybDAwoC6gLIYqaHR0
# cDovL2NybDQuZGlnaWNlcnQuY29tL2Fzc3VyZWQtY3MtZzEuY3JsMEwGA1UdIARF
# MEMwNwYJYIZIAYb9bAMBMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRpZ2lj
# ZXJ0LmNvbS9DUFMwCAYGZ4EMAQQBMIGCBggrBgEFBQcBAQR2MHQwJAYIKwYBBQUH
# MAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBMBggrBgEFBQcwAoZAaHR0cDov
# L2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEQ29kZVNpZ25p
# bmdDQS0xLmNydDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBBQUAA4IBAQCZYBH7
# HzONrpBWshHkFNOJm+WqWpuVTtFRwO6pr5peGvONH6znCfw1SOnN4YCu3SI/QDLt
# DaQP2QfV7/rXfP8Nla87Syxho/dwt/CbG6s3ZBAl7AUDCpRqhgLfJ4Oz1e9YFXoy
# VzOhUewZ30BzCiqSee8vagGYDSdI0ZVplMDLfvlavNlALn4c9sFCtdES+QJM7tHQ
# mceWMjdaebAYHfuaTkVeHN1qgKdEYRwoPxiRMp9Jf/R/4Z72bUNGZVqs1hrSAzCx
# fTjI54xXOqsjVdlo5y70F7QYbBqBy6twL/JBsYFq0KC7Yx8wSZGnUBz3s0IqJ3fB
# LPvpPGW7iMPMjtndMIIGozCCBYugAwIBAgIQD6hJBhXXAKC+IXb9xextvTANBgkq
# hkiG9w0BAQUFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5j
# MRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBB
# c3N1cmVkIElEIFJvb3QgQ0EwHhcNMTEwMjExMTIwMDAwWhcNMjYwMjEwMTIwMDAw
# WjBvMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQL
# ExB3d3cuZGlnaWNlcnQuY29tMS4wLAYDVQQDEyVEaWdpQ2VydCBBc3N1cmVkIElE
# IENvZGUgU2lnbmluZyBDQS0xMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
# AQEAnHz5oI8KyolLU5o87BkifwzL90hE0D8ibppP+s7fxtMkkf+oUpPncvjxRoaU
# xasX9Hh/y3q+kCYcfFMv5YPnu2oFKMygFxFLGCDzt73y3Mu4hkBFH0/5OZjTO+tv
# aaRcAS6xZummuNwG3q6NYv5EJ4KpA8P+5iYLk0lx5ThtTv6AXGd3tdVvZmSUa7uI
# SWjY0fR+IcHmxR7J4Ja4CZX5S56uzDG9alpCp8QFR31gK9mhXb37VpPvG/xy+d8+
# Mv3dKiwyRtpeY7zQuMtMEDX8UF+sQ0R8/oREULSMKj10DPR6i3JL4Fa1E7Zj6T9O
# SSPnBhbwJasB+ChB5sfUZDtdqwIDAQABo4IDQzCCAz8wDgYDVR0PAQH/BAQDAgGG
# MBMGA1UdJQQMMAoGCCsGAQUFBwMDMIIBwwYDVR0gBIIBujCCAbYwggGyBghghkgB
# hv1sAzCCAaQwOgYIKwYBBQUHAgEWLmh0dHA6Ly93d3cuZGlnaWNlcnQuY29tL3Nz
# bC1jcHMtcmVwb3NpdG9yeS5odG0wggFkBggrBgEFBQcCAjCCAVYeggFSAEEAbgB5
# ACAAdQBzAGUAIABvAGYAIAB0AGgAaQBzACAAQwBlAHIAdABpAGYAaQBjAGEAdABl
# ACAAYwBvAG4AcwB0AGkAdAB1AHQAZQBzACAAYQBjAGMAZQBwAHQAYQBuAGMAZQAg
# AG8AZgAgAHQAaABlACAARABpAGcAaQBDAGUAcgB0ACAAQwBQAC8AQwBQAFMAIABh
# AG4AZAAgAHQAaABlACAAUgBlAGwAeQBpAG4AZwAgAFAAYQByAHQAeQAgAEEAZwBy
# AGUAZQBtAGUAbgB0ACAAdwBoAGkAYwBoACAAbABpAG0AaQB0ACAAbABpAGEAYgBp
# AGwAaQB0AHkAIABhAG4AZAAgAGEAcgBlACAAaQBuAGMAbwByAHAAbwByAGEAdABl
# AGQAIABoAGUAcgBlAGkAbgAgAGIAeQAgAHIAZQBmAGUAcgBlAG4AYwBlAC4wEgYD
# VR0TAQH/BAgwBgEB/wIBADB5BggrBgEFBQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0
# dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0cDovL2NhY2Vy
# dHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNydDCBgQYD
# VR0fBHoweDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# QXNzdXJlZElEUm9vdENBLmNybDA6oDigNoY0aHR0cDovL2NybDQuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDAdBgNVHQ4EFgQUe2jOKarA
# F75JeuHlP9an90WPNTIwHwYDVR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8w
# DQYJKoZIhvcNAQEFBQADggEBAHtyHWT/iMg6wbfp56nEh7vblJLXkFkz+iuH3qhb
# gCU/E4+bgxt8Q8TmjN85PsMV7LDaOyEleyTBcl24R5GBE0b6nD9qUTjetCXL8Kvf
# xSgBVHkQRiTROA8moWGQTbq9KOY/8cSqm/baNVNPyfI902zcI+2qoE1nCfM6gD08
# +zZMkOd2pN3yOr9WNS+iTGXo4NTa0cfIkWotI083OxmUGNTVnBA81bEcGf+PyGub
# nviunJmWeNHNnFEVW0ImclqNCkojkkDoht4iwpM61Jtopt8pfwa5PA69n8SGnIJH
# QnEyhgmZcgl5S51xafVB/385d2TxhI2+ix6yfWijpZCxDP8xggRbMIIEVwIBATCB
# gzBvMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQL
# ExB3d3cuZGlnaWNlcnQuY29tMS4wLAYDVQQDEyVEaWdpQ2VydCBBc3N1cmVkIElE
# IENvZGUgU2lnbmluZyBDQS0xAhAFXHiCBIbnyVa0P26SLj68MAkGBSsOAwIaBQCg
# gZ4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwG
# CisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFB2IQ/8COI645h5MIpvI4Jj9qPHo
# MD4GCisGAQQBgjcCAQwxMDAuoBiAFgBDAGwAbwB1AGQAcABhAGcAaQBuAGehEoAQ
# d3d3Lm51bWVjZW50LmNvbTANBgkqhkiG9w0BAQEFAASCAQAcsNWYtyPiBNfSKyeW
# 2IKWwHLpNghQJFFksQhxuvVma44b9qBwjxTJH37vKA/OGKYi90vVtbPs1cVWZW0m
# XUtl3zjj06AqjnY66ashia18yIIpP2gUJnN9EwihyLHUBFKYxQOsz8ZW5BMkRjEF
# hjC1x6Hq35QZBvYIwZlwL8XN3pAOwkHH1TtTuFONKu2WagQ9Y5kFUvFbgF9Ald0A
# LUtTNi45W+wpkI1SSW5NeR86asK14k2Iiwe220uyeUVaQmEK+WrJvRpY+HCnNL50
# 87tb5OdyBygDzqJcRUmNuFJtU5CZe4EtNzyMYlNh0oqeVLov3PTmiJcL0EjXy9V0
# H5/DoYICCzCCAgcGCSqGSIb3DQEJBjGCAfgwggH0AgEBMHIwXjELMAkGA1UEBhMC
# VVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMTAwLgYDVQQDEydTeW1h
# bnRlYyBUaW1lIFN0YW1waW5nIFNlcnZpY2VzIENBIC0gRzICEA7P9DjI/r81bgTY
# apgbGlAwCQYFKw4DAhoFAKBdMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJ
# KoZIhvcNAQkFMQ8XDTIwMDIyMjAxMjUwOVowIwYJKoZIhvcNAQkEMRYEFBwbs09c
# sty4XOErrX1pAllo6s4cMA0GCSqGSIb3DQEBAQUABIIBABws8wSGTR3SVM8rL7GY
# xNlIESJP4RddDaeOMyQ/lRNtlGoV0w+ZpI9zt/fUOm21swBpBU3T4vGmyAt3gyVu
# zicr6apwf1KfxpZOOESE3bch4n90PYFfrdXuwD6eKF4YtB0TT6/WHpz1UE+0huKd
# CcxgmwqKpz23Ny3WSmJjwn3kd+8edDnvRiSdH/ld7bbdUjI084l7Qcu57yajQoMc
# oKvCGykl6W8yO8DlmNWq+GIMDOkA5YG9hhVRUfB7oxeVdpyX1+vt/GM0pF1EVZc/
# rUBs+RhHgJPskYkR66msx38P9DP2k12/WZYiHBvHV/RAGxlFPTpfHUZtPkUPUa3H
# +0U=
# SIG # End signature block
