# Cloudpaging Automated-Packaging
This is a repository of JSON configuration files to showcase automated packaging with Cloudpaging technology.

Numecent does not offer professional support services for automated packaging at this time. All support efforts are community driven. Please visit our [community discussion forum here](https://numecent.freshdesk.com/support/discussions/forums/1000229144).

## Overview
Cloudpaging is a foundational technology framework and represents Numecent's vision to transform native software delivery, deployment and provisioning from the Cloud, both public and private, and on-premises. This patented technology makes it possible to lift and shift existing client applications to a new operating environment without all the hassle and expense of upgrading to new versions of your existing software.

The Cloudpaging Studio is where the science begins in the form of application packaging. The Studio prepares the application for automated deployment, updates, and access settings based upon the predetermined permission levels within your organization. You can package your apps for Windows XP or 7 and easily lift and shift them over to Windows 10. 

For more information, please visit [www.numecent.com](https://www.numecent.com/).

## JSON Helper Script  
This PS1 script helps generating the automated packaging JSON file and starting the packaging process.  

## Requirements  
* Cloudpaging Studio 9.3.1 or higher.  
* Automated Packaging Files from GitHub.  
* JSON Helper files from GitHub.  

##Install Instructions  

Download contents of Powershell-Generator to C:\NIP_Software 

Recommended: Download and utilize Studio Capture Filter Definition  

Files (https://numecent.freshdesk.com/support/solutions/articles/1000264620-studio-capture-filterhttps://numecent.freshdesk.com/support/solutions/articles/1000264620-studio-capture-filter-definition-filesdefinition-files)  

## Arguments  

-**FilePath** – Path to installer EXE/MSI.  

-**Name** – Appset name, if not specified, defaults to “filename cloudpaged”.  

-**Description** – Appset description, if not specified, defaults to a generic description with filename.  

-**Arguments** – Installer arguments. If not specified and the “-FilePath” is an MSI, defaults to “/qn /norestart”. If “-FilePath” in an EXE or a script, no default is set, and will launch as-is.   

-**StudioCommandline** – Command line for the appset.   

-**Outputfolder** – Path for appset (STP) and Workspace (STW) files. If not specified, defaults to “C:\NIP_Software\Output”.   

-**CustomCommandlines** – Extra command capture.  

-**RegistryModify** – Adds registry specified in the $Registrymodify (PSCustomObject) section.  

-**CustomRegistryDisposition** – Sets the target keys to the specified disposition, recurse if desired, specified in the $CustomRegistryDisposition (PSCustomObject) section.  

-**CustomFileDisposition** – Set the target file/folder to the specified disposition, recurse if desired, specified in the $CustomFileDisposition (PSCustomObject) section.  

-**FileAddition** – Generates/adds a text file in the specified path, with the specified text, specified in the $Fileaddition (PSCustomObject) section.  

## PS CustomObjects Examples  

* File Addition  

$Fileaddition =@()
$Fileaddition += [PSCustomObject]@{
FileName = "master_preferences"
FileDestination =  "C:\Program Files\Google\Chrome\Application\"
FileContent = @"
{
"homepage": "http://www.google.com",
"homepage_is_newtabpage": false,"
"browser": {
"show_home_button": true,
"check_default_browser" : false"
}
}
"@
}

* Registry modify
$Registrymodify =@()
$Registrymodify += [PSCustomObject]@{
Location = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Update"
values = "UpdateDefault=dword:00000000",
"DisableAutoUpdateChecksCheckboxValue=dword:00000001",
"AutoUpdateCheckPeriodMinutes=dword:00000000"

}

* Custom Registry Disposition 

$CustomRegistryDisposition =@()
$CustomRegistryDisposition += [PSCustomObject]@{
Location = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup"
Layer = 4
Recurse = "true"
}

* Custom File Disposition  

$CustomfileDisposition =@()
$CustomfileDisposition += [PSCustomObject]@{
Path = "C:\Program Files\Google\Chrome\Application\SetupMetrics"
Layer = 4
Recurse 
}

## Scripts with Examples  

**Create JSON and package** (Auto-Generate-and-Create-Package.ps1) – This script creates the JSON and runs automated packaging.   

The script below captures Chrome, with Zoom on top (as a CustomCommandine) along with parameters. It also adds registry keys (via RegistryModify), sets a registry disposition (via CustomRegistryDisposition), sets a file disposition to a folder (via CustomFileDisposition), and creates a custom file (via FileAddition).   

The second example is to capture Acrobat with an MST (using Arguments).  

• 	Example #1:  

& C:\NIP_software\Auto-Generate-and-Create-Package.ps1 -FilePath C:\NIP_software\googlechromestandaloneenterprise64.msi -CustomCommandlines 'msiexec.exe /i "C:\NIP_software\Zoom\installer_cfg\ZoomInstallerVDI.msi"', 'reg add  "HKLM\SOFTWARE\Policies\Zoom\Zoom Meetings\VDI" /v EnableShareAudioSound /t  REG_DWORD /d 1 /f', 'reg add "HKLM\SOFTWARE\Policies\Zoom\Zoom Meetings\VDI" /v Fallbackmode /t REG_DWORD /d 6 /f', 'reg add "HKLM\SOFTWARE\Policies\Zoom\Zoom Meetings\VDI" /v LogLevel /t REG_DWORD /d 4 /f'

• 	Example #2:  

& C:\NIP_software\Auto-Generate-and-Create-Package.ps1 -FilePath 'C:\NIP_Software\Acro Pro.msi' -Arguments 'TRANSFORMS="C:\NIP_Software\Acro Pro.mst"'  

## Additional Options: (defaults in bold) 

-**Compression** – Set compression type to use ('**LZMA**', 'NONE') 

-**Encryption** – Set encryption type to use ('**AES-256-Enhanced**', 'AES-256', 'None') 

-**DefaultDispositionLayer** – Set default disposition layer for package to use (‘**3**’, '4 ') 

-**RegistryExclusions** – Set registry exclusions e.g  HKLM\SOFTWARE\ 

-**FileExclusions** – Set file exclusions e.g  c:\temp 

-**ProcessesAllowedAccessToLayer4** – Set process names that can access layer 4 assets e.g “cmd.exe”, “powershell.exe” 

-**ProcessesDeniedAccessToLayers3and4** – Set process names that cannot access layer 3 or 4 assets e.g “cmd.exe”, “powershell.exe” 

-**CaptureAllProcesses** – Set whether all processes should be captured ($True,**$False**) 

-**IncludeSystemInstallationProcesses** – Set whether to include system installation process ($True,**$False**) 

-**IgnoreChangesUnderInstallerPath** – Set whether to ignore changes in install directory(**$True**,$False) 

-**ReplaceRegistryShortPaths** – Set whether to replace registry short paths (**$True**,$False) 

-**IncludeChildProccesses** – Set whether to include child processes (**$True**,$False) 

-**Prerequisites** – Set whether prerequisites to capturing the package need to occur ($True,**$False**) 

-**PrerequisiteCommands** – Set prerequitsiite commands to run e.g “cmd.exe /c copy C:\temp\tempfile1.config c:\appdirectory\” 

-**DefaultServiceVirtualizationAction** – Set what the default service vitulization action is ('**None**', 'Register', 'Start')] 

-**FinalizeIntoSTP** – Set whether to create and stp (**$True**,$False) 

-**IncludeSourceDirectory** – Set whether to create to copy the source folder where the install media resides specified in -FilePath ($True,**$False**) (Additional note If you are using “C:\NIP_Software” for your installers, please be sure to place the install source in a subfolder when using this option.) 

### **Create JSON only** (CreateJson.ps1) – This script creates a JSON for later use.  

*	& CreateJson.ps1 with the same parameters as **Create JSON and package**.  

### **Package from existing JSON** (Auto_Install_from_json.ps1) – This script runs the automated packaging from a previously created JSON.  

*	Copy a previously generated JSON using 'CreateJson.ps1', its corresponding MSI/EXE, and any supplementary install files to 'C:\NIP_software\Auto'   

* Run 'C:\NIP_software\Scripts\Auto_Install_from_json.ps1'   
