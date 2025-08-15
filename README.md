## CITS scripts

### ⚙️ Setup & Usage

Project File Structure

```
📁 NewPCSetup/
│
├── 🗔 NewPC.ps1
│   (Main Script File)
│
├── ⚙️ config.json
│   (Configuration File)
│
├── 🗖 UninstallOneDrive.ps1
│   (Helper Script)
│
├── 🗗 7z_Assoc_OnlyWin10.bat
│   (Helper Script)
│
├── 📦 7zXXX-x64.msi
│   (Software Installer)
│
└── 📦 AnyDesk.exe
    (Software Installer)
```

### File Descriptions

| File | Description | Required? |
| :--- | :--- | :--- |
| **`NewPC.ps1`** | The main PowerShell script that executes all setup and configuration tasks. It contains the core logic for system checks, user interaction, and task orchestration. | **Yes** |
| **`config.json`** | A critical configuration file in JSON format. It contains two main sections: `appRemoval` (lists of UWP apps to uninstall for Win10/Win11) and `registrySettings` (key-value pairs for configuring the Content Delivery Manager). | **Yes** |
| **`UninstallOneDrive.ps1`** | A helper PowerShell script designed to completely and silently remove OneDrive from the system. It is called by the main script if the user confirms this action. | Optional |
| **`7z_Assoc_OnlyWin10.bat`** | A helper batch script that sets the default file associations for archives (`.zip`, `.7z`, `.rar`, etc.) to 7-Zip. It is specifically designed for and only executed on Windows 10 systems. | Optional |
| **`7zXXX-x64.msi`** | The official MSI installer for the 64-bit version of 7-Zip. The main script looks for a file matching `7z*.msi` to perform a silent installation. | **Yes**¹ |
| **`AnyDesk.exe`** | The official executable installer for AnyDesk. The script uses this file to perform a silent, system-wide installation and configure unattended access. | **Yes**¹ |

---
¹ **Note:** These installer files are only strictly required for the **Offline Version** of the script. In the **Full Version**, if these files are not found, the script will offer to download them from their official websites.

### 📜 Script Versions

Two versions of the script are provided.

##### Full Version (With Download Support)
This version includes the `Invoke-RobustDownload` function. If `7-Zip` or `AnyDesk` installers are not found locally, it will prompt the user to download them from the official websites.

##### Offline Version
This version **does not** include the download functionality. It assumes all necessary installers are already present in the script's folder. If an installer is not found, the corresponding installation step is skipped.

---

### Used projects :
Thanks a lot to all of you!
#### Turn Off ContentDeliveryManager Suggested Content
> Created By: Paul Black
>
> Created On: 03-Sep-2021
>
> [Windows 10 Forums / How to Turn On or Off Automatically Installing Suggested Apps in Windows 10](https://www.tenforums.com/tutorials/68217-turn-off-automatic-installation-suggested-apps-windows-10-a.HTML)
#### UninstallOneDrive
> AUTHOR asherto
>
> COMPANYNAME asheroto
>
> PROJECTURI https://github.com/asheroto/UninstallOneDrive
