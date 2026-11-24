# DefenderGuard (Microsoft Defender GUI)

A modern, Quick Heal-style Windows desktop interface built on **C# WPF (.NET 8)** that controls Windows 10/11's built-in **Microsoft Defender** engine via official PowerShell cmdlets.

## Features
- **Security Dashboard:** Live status banner ("You're Protected"), Real-Time Protection, Behavior Monitoring, Tamper Protection, and signature age.
- **Scans:** One-click Quick Scan, Full Scan, and Custom Folder Scan (`Start-MpScan`).
- **Protection Controls:** Toggle Real-Time Protection, Advanced Cloud Protection, and PUA Blocking (`Set-MpPreference`).
- **Threat History & Firewall:** View recent threat detections (`Get-MpThreatDetection`) and Windows Firewall profiles (`Get-NetFirewallProfile`).
- **Auto-Build EXE on GitHub:** Includes `.github/workflows/build-exe.yml` to compile a standalone `DefenderGuard.exe` in the cloud.

## How to Build the `.exe` on GitHub
1. Create a new repository on GitHub.
2. Upload all files from this folder (including the hidden `.github/workflows/build-exe.yml` file).
3. Go to the **Actions** tab in your GitHub repository.
4. Select **Build DefenderGuard EXE** and click **Run workflow** (or push any commit to `main`).
5. Once finished, download **DefenderGuard-win-x64** from the **Artifacts** section at the bottom of the workflow run.
