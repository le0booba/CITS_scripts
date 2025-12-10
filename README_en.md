## CITS scripts

### 🛠 Setup & Usage

#### Project File Structure

```
🗀 NewPC/
│
├── 🗔 NewPC.ps1
│   (Main Script File | WITH 7Zip & AnyDesk latest version download function)
│
├── 🗔 NewPC_offline.ps1
│   (Main Script File | WITHOUT 7Zip & AnyDesk latest version download function)
│
├── 🗔 Get-PCInventory.ps1
│   (System Information Collection Script)
│
├── 🗗 Start_PS.bat
│   (PowerShell Launcher | -NoProfile -NoExit -ExecutionPolicy Bypass)
│
├── ⏣ config.json
│   (Bloatware removal Configuration File)
│
├── 🗖 UninstallOneDrive.ps1
│   (OneDrive Removal Script)
│
├── 🗗 7z_Assoc_OnlyWin10.bat
│   (7-Zip File Association Script - only for Win10)
│
├── 📦 7zXXX-x64.msi
│   (7-Zip MSI Installer - Optional)
│
├── 📦 AnyDesk.exe
│   (AnyDesk Installer - Optional)
│
└── 🗔 ApplyUI-tweaks.ps1
    (UI Tweaks Application Script)
```

#### File Descriptions

| File | Description | Required? |
| :--- | :--- | :--- |
| **`NewPC.ps1`** | The main PowerShell script with download capabilities. Executes all setup tasks including app removal, system configuration, software installation, and user management. Can download missing installers from official sources. | **Yes** |
| **`NewPC_offline.ps1`** | Offline version of the main script without download functionality. Requires all installers to be present locally. Ideal for environments without internet access. | Alternative |
| **`Get-PCInventory.ps1`** | System information collection script that generates detailed hardware and software reports in both CSV and HTML formats. Can be run independently or called by main scripts. | Optional |
| **`Start_PS.bat`** | Administrative PowerShell launcher that checks for admin privileges and sets the correct execution policy. Provides a convenient way to start PowerShell sessions. | Helper |
| **`config.json`** | Critical configuration file containing app removal lists for Windows 10/11 and registry settings for disabling suggested content and ads. | **Yes** |
| **`UninstallOneDrive.ps1`** | Specialized script for complete OneDrive removal from Windows systems. Called by main scripts when user opts to remove OneDrive. | Optional |
| **`7z_Assoc_OnlyWin10.bat`** | Batch script for setting 7-Zip as default handler for archive formats. Windows 10 specific due to file association differences in Windows 11. | Optional |
| **`7zXXX-x64.msi`** | Official 7-Zip MSI installer (64-bit). Script looks for files matching `7z*.msi` pattern for silent installation. | Optional¹ |
| **`AnyDesk.exe`** | Official AnyDesk executable installer. Used for silent system-wide installation with automatic password configuration. | Optional¹ |
| **`ApplyUI-tweaks.ps1`** | UI tweaks application script for all users (including offline profiles and default profile). Configures explorer settings, taskbar, search, and other interface elements. | Optional |

¹ **Note:** These installer files are only strictly required for the **Offline Version**. The **Full Version** can download them automatically if not found locally.

---

### ⚙️ Configuration

#### `config.json` Structure
```json
{
  "appRemoval": {
    "Win11": [
        "App.Name1",
        "App.Name2"
    ],
    "Win10": [
        "App.Name3",
        "App.Name4"
    ]
  },
  "registrySettings": {
    "SettingName": 0,
    "AnotherSetting": 1
  }
}
```

### 🚀 Quick Start
**Run as Administrator**: Right-click `Start_PS.bat` → "Run as administrator"

### 💽 Script Versions

#### Full Version (`NewPC.ps1`)
This version includes the `Invoke-RobustDownload` function. If `7-Zip` or `AnyDesk` installers are not found locally, it will prompt the user to download them from the official websites.

#### Offline Version (`NewPC_offline.ps1`)
This version does not include the download functionality. It assumes all necessary installers are already present in the script's folder. If an installer is not found, the corresponding installation step is skipped.

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
