# Alyssia - Android Application Security Analysis Tool

## 📌 Overview
**Alyssia** is a bash-based tool designed to help security engineers and researchers analyze Android applications.  
It automates static analysis by:
- Checking for required dependencies.
- Decompiling APKs using `jadx`.
- Searching for potential security misconfigurations and sensitive references in the decompiled code.
- Printing findings live in the terminal and saving them to a `findings.txt` file.
- Preparing the report by storing the output in `alyssia_report.txt` file

---

## ⚙️ Requirements

- **jadx** – for decompiling APK files.
- **grep / egrep** – for keyword searches.
- **xmlstarlet** – for Android manifest parsing.

If the requirements are not installed the script will install it automatically.

## ⚠️ Note

- while giving the directory of the .apk file, please give it from the root diretory. If the .apk location is given from the current working directory, you may face some issues while running the script.

## 🚀 Usage

### Make the script executable
```bash
chmod +x alyssia.sh
```

### Run the tool against an APK
```bash
./alyssia.sh -d <apk_path>
```

### Arguments
| Argument        | Description                                |
|-----------------|--------------------------------------------|
| `-d <apk_path>` | Path to the target APK file                |
| `-h, --help`    | Display help/usage information             |

---

## 📂 Output
- **/<apkname>** Folder created to store the decompiled apk file along with the findings.txt and the alyssia_report.txt.
- **Terminal:** Displays all the findings from the analysis, with just the number of findings in the source code analysis to reduce the visual clutter.  
- **findings.txt:** A full list of all findings will be saved in the working directory.
- **alyssia_report.txt:** Findings from the analysis which are shown in the terminal is stored here.

---

## 🔍 Example
```bash
./alyssia.sh -d /home/kali/sample.apk
```

### Example Output
```
------------------------------------------------ 
|       _    _  __   ______ ____ ___    _      |
|      / \  | | \ \ / / ___/ ___|_ _|  / \     |
|     / _ \ | |  \ V /\___ \__   | |  / _ \    |
|    / ___ \| |___| |  ___) |__) | | / ___ \   |
|   /_/   \_\_____|_| |____/____/___/_/   \_\  |
|                                              |
------------------------------------------------
Android application Security Analysis tool
- Creators: Profon3 & Valkyrie
================================================================ 
Checking whether the required tools are installed
-------------------------------------
- jadx is installed
- xmlstarlet is installed
- Path: /home/kali/sample.apk
================================================================ 
Commencing the analysis
-------------------------------------
- Decompiling the apk file
- Decompiled apk file path: /home/kali/sample/decompiled_java
INFO  - loading ...
INFO  - processing ...
ERROR - finished with errors, count: 6                       
================================================================ 
Commencing analysis on the application's configuration
================================================================ 
Checking for the Minimum supported SDK version:
-------------------------------------
- Minimum SDK version supported in the application: 24
- The Minimum SDK version aligns with security practices.
================================================================ 
Checking whether the Backup function is enabled
-------------------------------------
- Allow Backup functionality is set to : true
- Set 'allowBackup' to false to prevent data leakage.
================================================================ 
Checking debuggable setting
-------------------------------------
- Debuggable flag is set to : true
- Disable 'debuggable' in production.
================================================================ 
Checking usesCleartextTraffic setting
-------------------------------------
- usesCleartextTraffic is set to : true
- Set 'usesCleartextTraffic' to false to avoid MITM risks.
================================================================ 
Checking dangerous permissions
-------------------------------------
- Dangerous permissions detected:
  - READ_CONTACTS
  - SEND_SMS
  - RECEIVE_SMS
  - READ_EXTERNAL_STORAGE
================================================================ 
Checking taskAffinity settings
-------------------------------------
- All taskAffinity settings are safe.
================================================================ 
Checking launchMode settings
-------------------------------------
- Risky launchModes detected:
  - com.Sample.ExternalAuthLogin (singleTask)
================================================================ 
Checking exported activity components
-------------------------------------
- Exported activity components found (explicit or implicit):
  - com.Sample.ExternalAuthLogin (exported=true)
  - com.Sample.MyProfile (exported=true)
  - com.Sample.Deeplink (exported=true)
================================================================ 
Checking exported service components
-------------------------------------
- Exported service components found (explicit or implicit):
  - com.Sample.SMSService (exported=true)
  - com.Sample.BackgroundService (exported=MISSING)
================================================================ 
Checking exported provider components
-------------------------------------
- Exported provider components found (explicit or implicit):
  - com.Sample.provider.UserProfileProvider (exported=true)
================================================================ 
Commencing Analysis on Application's Source code:
-------------------------------------
================================================================ 
Networking & SSL
-------------------------------------
  [!] android.intent -> 0 matches
  [!] Intent -> 0 matches
  [!] Content Providers & urls -> 0 matches
  [OK] Service references -> 0 matches
  [!] Broadcast Receiver reference -> 0 matches
  [OK] Host name Verifier -> 0 matches
  [!] Trust Manager references -> 0 matches
  [!] Check Server trusted -> 0 matches
  [!] Searching for URLs -> 0 matches
  [!] HTTP headers -> 0 matches
  [OK] UDP and TCP Sockets -> 0 matches
  [!] Client certificates -> 0 matches
  [OK] SSL certificate pinning -> 0 matches
  [!] SSL connections -> 0 matches
  [!] WebView activity -> 0 matches
  [!] addJavascriptInterface references -> 0 matches
  [!] setJavaScriptEnabled references -> 0 matches
  [!] setAllowFileAccess references -> 0 matches
  [OK] setSavePassword references -> 0 matches
================================================================ 
Final Summary
-------------------------------------
 Manifest checks run   : 11
 Manifest findings     : 4
 Source checks run     : 47
 Source matches found  : 0
------------------------------------------------
 Networking & SSL -> 0 matches
 App Hardening & Secrets -> 0 matches
 Storage & File Handling -> 0 matches
 Cryptography -> 0 matches
 Code Execution & SQL -> 0 matches
------------------------------------------------
 Detailed findings are available in: /home/kali/sample/findings.txt
 Assessment Report is available in: /home/kali/sample/alyssia_report.txt
================================================================ 
End of Report
-------------------------------------

```

## 🛡️ Disclaimer
This tool is intended **for educational and research purposes only**.  
Do not use it against applications without proper authorization. The authors are not responsible for misuse.

