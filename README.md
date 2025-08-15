# CITS scripts
Конечно. Вот стильный, но минималистичный `README.md` файл, который использует значки (badges), эмодзи и форматирование для улучшения читаемости и профессионального вида.

---

# PowerShell New PC Setup Script

[![PowerShell Version](https://img.shields.io/badge/PowerShell-5.1%2B-blue)](https://docs.microsoft.com/en-us/powershell/) [![Windows Version](https://img.shields.io/badge/Windows-10%20%7C%2011-blue)](https://www.microsoft.com/windows) [![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

> A robust PowerShell script for automating the initial setup and configuration of new Windows workstations.

This tool is designed for IT professionals to standardize, accelerate, and improve the reliability of the PC preparation process.

- [✨ Features](#-features)
- [📦 Requirements](#-requirements)
- [⚙️ Setup & Usage](#️-setup--usage)
- [🔧 Configuration](#-configuration)
- [📜 Script Versions](#-script-versions)
- [⚖️ License](#️-license)

---

## ✨ Features

The script performs a series of automated tasks, requesting confirmation at key stages.

#### **System Cleanup**
*   **UWP App Removal:** Uninstalls bloatware and adware based on lists in `config.json`.
*   **Content Delivery Manager:** Disables automatic installation of "suggested" apps and ads.
*   **OneDrive Removal:** Optionally runs an external `UninstallOneDrive.ps1` script for complete removal.

#### **Core Configuration**
*   **PC Renaming:** Prompts for a new computer name in a GUI window with input validation.
*   **`helper` User Creation:** Creates a local administrator account named `helper` with a cryptographically secure, generated password.
*   **Security Hardening:** Sets all user passwords to never expire and ensures the `helper` account is only a member of the "Administrators" group.

#### **System & Security Settings**
*   **Power Management:** Disables hibernation and configures power plans for AC and battery modes.
*   **Windows Firewall:** Disables all firewall profiles.
*   **Remote Access:** Enables Remote Assistance and RDP (for compatible Windows editions) using language-independent firewall rules.

#### **Software Installation**
*   **7-Zip:** Installs 7-Zip from a local `.msi` package.
*   **AnyDesk:** Installs AnyDesk from a local `.exe` package and automatically configures a secure password for unattended access.

#### **System Inventory**
*   **Data Collection:** Gathers detailed system information (OS, hardware, network, users).
*   **Reporting:** Saves the collected data into `.csv` and `.html` files for documentation and asset management.

#### **Best Practices & Reliability**
*   **Idempotent:** The script can be run multiple times without causing errors. It checks the system's current state before making changes.
*   **Reliable Downloads (Full Version):** Uses the Windows **BITS** service to download files, which automatically resumes on network interruption. A robust fallback with integrity checks is included.
*   **Silent Failure Detection:** Checks the exit codes (`$LASTEXITCODE`) of external programs to ensure critical operations like password setting were successful.
*   **Language-Independent:** Most operations are designed to work on any language version of Windows by using SIDs or internal rule names instead of localized display names.
*   **External Configuration:** App lists and registry settings are managed via `config.json`, making customization easy without editing the script's logic.

## 📦 Requirements
*   Windows 10 / 11 (Pro, Enterprise, or Education for RDP features).
*   PowerShell 5.1 (included in Windows).
*   Execution as an Administrator.
*   Internet connection (for the full version with download support).

## ⚙️ Setup & Usage
1.  Create a dedicated folder (e.g., `C:\NewPCSetup`).
2.  Place the main `NewPC.ps1` script in this folder.
3.  Place the required configuration and helper files (see [Configuration](#-configuration)) in the same folder.
4.  Run PowerShell as an Administrator.
5.  Navigate to the script's directory:
    ```powershell
    cd C:\NewPCSetup
    ```
6.  Allow script execution for the current session:
    ```powershell
    Set-ExecutionPolicy Bypass -Scope Process -Force
    ```
7.  Run the script:
    ```powershell
    .\NewPC.ps1
    ```
8.  Follow the prompts in the graphical dialog boxes.

## 🔧 Configuration
The script relies on a few external files being present in the same directory:

*   `config.json` (Required): A JSON file containing lists of UWP apps to remove and registry settings to apply.
*   `UninstallOneDrive.ps1` (Optional): A helper script for completely removing OneDrive.
*   `7z_Assoc_OnlyWin10.bat` (Optional): A batch file to set 7-Zip file associations on Windows 10.
*   **Installers** (Required):
    *   7-Zip installer (`7z*.msi`)
    *   AnyDesk installer (`AnyDesk.exe`)

## 📜 Script Versions

Two versions of the script are provided to suit different environments.

### Full Version (With Download Support)
This version includes the `Invoke-RobustDownload` function. If `7-Zip` or `AnyDesk` installers are not found locally, it will prompt the user to download them from the official websites.

### Offline Version
This version **does not** include the download functionality. It assumes all necessary installers are already present in the script's folder. If an installer is not found, the corresponding installation step is skipped.

## ⚖️ License
This project is licensed under the MIT License.
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
