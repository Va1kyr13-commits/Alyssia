#!/bin/bash

BANNER="------------------------------------------------ 
|       _    _  __   ______ ____ ___    _      |
|      / \  | | \ \ / / ___/ ___|_ _|  / \     |
|     / _ \ | |  \ V /\\___ \\__   | |  / _ \    |
|    / ___ \| |___| |  ___) |__) | | / ___ \   |
|   /_/   \_\_____|_| |____/____/___/_/   \_\  |
|                                              |
------------------------------------------------"


RED='\033[1;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BRIGHTCYAN='\033[1;36m'
NC='\033[0m' 

print_section() {
    echo "================================================================ "
    echo "$1"
    echo "-------------------------------------"
}
echo -e "${BRIGHTCYAN}$BANNER${NC}"
echo -e "${GREEN}Android application Security Analysis tool${NC}"
echo -e "${YELLOW}- Creators: Profon3 & Va1kyr13${NC}"

print_section "Checking whether the required tools are installed"
if command -v jadx &> /dev/null; then
    echo -e "${GREEN}- jadx is installed${NC}"
else
    echo -e "${RED}- jadx is not installed. Installing...${NC}"
    sudo apt update && sudo apt install -y jadx
fi
if command -v xmlstarlet &> /dev/null; then
    echo -e "${GREEN}- xmlstarlet is installed${NC}"
else
    echo -e "${RED}- xmlstarlet is not installed. Installing...${NC}"
    sudo apt update && sudo apt install -y xmlstarlet
fi

extract_attr() {
    grep -oP "$2\\s*=\\s*\"[^\"]*\"" "$1" | head -1 | cut -d '"' -f2
}

while getopts "d:u:h" opt; do
    case "$opt" in
        d)
            apk_file=$OPTARG
            echo -e "${BLUE}- Path: $apk_file${NC}"
            foldername_withext=$(basename "$apk_file")
            foldername="${foldername_withext%.*}"
            mkdir -p $foldername
            cd $foldername
            mkdir -p decompiled_java
            decompiled_filepath=$(pwd)
	        findings_file="$decompiled_filepath/findings.txt"
            report_file="$decompiled_filepath/alyssia_report.txt"   
            print_section "Commencing the analysis"
            echo -e "${GREEN}- Decompiling the apk file${NC}"
            echo -e "${BLUE}- Decompiled apk file path: $decompiled_filepath/decompiled_java${NC}"
            jadx "$apk_file" -d "$decompiled_filepath/decompiled_java"
            cd "$decompiled_filepath/decompiled_java/resources" || exit 1
            xml_file="AndroidManifest.xml"

            if [[ ! -f "$xml_file" ]]; then
                echo -e "${RED}AndroidManifest.xml not found!${NC}"
                exit 1
            fi
            exec > >(tee >(sed 's/\x1B[[0-9;]*[JKmsu]//g' > "$report_file")) 2>&1 
            echo "================================================================ "
            echo -e "${GREEN}Commencing analysis on the application's configuration${NC}"

            manifest_checks=0
            manifest_matches=0

            print_section "Checking for the Minimum supported SDK version:"
            ((manifest_checks++))
            min_sdk=$(grep -oP 'android:minSdkVersion\s*=\s*"\K[0-9]+' "$xml_file")
            echo -e "${BLUE}- Minimum SDK version supported in the application: $min_sdk${NC}"
            if [[ -z "$min_sdk" ]]; then
                echo -e "${YELLOW}- minSdkVersion not found in AndroidManifest.xml!${NC}"
                ((manifest_matches++))
            elif (( min_sdk <= 18 )); then
                echo -e "${RED}- Use a minSdkVersion higher than 18 for better security.${NC}"
                ((manifest_matches++))
            else
                echo -e "${GREEN}- The Minimum SDK version aligns with security practices.${NC}"
            fi

          
            print_section "Checking whether the Backup function is enabled"
            ((manifest_checks++))
            allow_backup=$(extract_attr "$xml_file" "android:allowBackup")
            echo -e "${BLUE}- Allow Backup functionality is set to : $allow_backup${NC}"
            if [[ "$allow_backup" == "true" ]]; then
                echo -e "${YELLOW}- Set 'allowBackup' to false to prevent data leakage.${NC}"
                ((manifest_matches++))
            else
                echo -e "${GREEN}- Backup settings align with recommended practices.${NC}"
            fi

           
            print_section "Checking debuggable setting"
            ((manifest_checks++))
            debuggable=$(extract_attr "$xml_file" "android:debuggable")
            echo -e "${BLUE}- Debuggable flag is set to : $debuggable${NC}"
            if [[ "$debuggable" == "true" ]]; then
                echo -e "${RED}- Disable 'debuggable' in production.${NC}"
                ((manifest_matches++))
            else
                echo -e "${GREEN}- Debuggable is properly disabled.${NC}"
            fi

         
            print_section "Checking usesCleartextTraffic setting"
            ((manifest_checks++))
            cleartext=$(extract_attr "$xml_file" "android:usesCleartextTraffic")
            echo -e "${BLUE}- usesCleartextTraffic is set to : $cleartext${NC}"
            if [[ "$cleartext" == "true" ]]; then
                echo -e "${RED}- Set 'usesCleartextTraffic' to false to avoid MITM risks.${NC}"
                ((manifest_matches++))
            else
                echo -e "${GREEN}- Cleartext traffic is disabled.${NC}"
            fi


            print_section "Checking dangerous permissions"
            ((manifest_checks++))
            dangerous_permissions=(
                "READ_CONTACTS" "WRITE_CONTACTS" "READ_SMS" "SEND_SMS" "RECEIVE_SMS"
                "ACCESS_FINE_LOCATION" "ACCESS_COARSE_LOCATION" "RECORD_AUDIO"
                "CAMERA" "READ_EXTERNAL_STORAGE" "WRITE_EXTERNAL_STORAGE"
            )
            found=()
            for perm in "${dangerous_permissions[@]}"; do
                grep -q "$perm" "$xml_file" && found+=("$perm")
            done
            if (( ${#found[@]} > 0 )); then
                echo -e "${YELLOW}- Dangerous permissions detected:${NC}"
                for p in "${found[@]}"; do echo -e "${PURPLE}  - $p${NC}"; done
                ((manifest_matches++))
            else
                echo -e "${GREEN}- No dangerous permissions found.${NC}"
            fi

            
            print_section "Checking taskAffinity settings"
            ((manifest_checks++))
            package_name=$(extract_attr "$xml_file" "package")
            flagged_affinities=()
            while IFS=$'\t' read -r activity_name affinity; do
                if [[ -n "$affinity" && "$affinity" != "$package_name" && "$affinity" != "$package_name"* ]]; then
                    flagged_affinities+=("$activity_name:$affinity")
                fi
            done < <(xmlstarlet sel -t -m "//activity" -v "@android:name" -o $'\t' -v "@android:taskAffinity" -n "$xml_file")

            if (( ${#flagged_affinities[@]} > 0 )); then
                echo -e "${YELLOW}- Potentially unsafe taskAffinity settings found:${NC}"
                for item in "${flagged_affinities[@]}"; do echo -e "${PURPLE}  - $item${NC}"; done
                ((manifest_matches++))
            else
                echo -e "${GREEN}- All taskAffinity settings are safe.${NC}"
            fi

            
            print_section "Checking launchMode settings"
            ((manifest_checks++))
            risky_modes=("singleTask" "singleInstance")
            risky_activities=()
            while IFS=$'\t' read -r activity_name launch_mode; do
                for mode in "${risky_modes[@]}"; do
                    if [[ "$launch_mode" == "$mode" ]]; then
                        risky_activities+=("$activity_name ($launch_mode)")
                    fi
                done
            done < <(xmlstarlet sel -t -m "//activity" -v "@android:name" -o $'\t' -v "@android:launchMode" -n "$xml_file")

            if (( ${#risky_activities[@]} > 0 )); then
                echo -e "${YELLOW}- Risky launchModes detected:${NC}"
                for act in "${risky_activities[@]}"; do echo -e "${PURPLE}  - $act${NC}"; done
                ((manifest_matches++))
            else
                echo -e "${GREEN}- No risky launchModes detected.${NC}"
            fi

            
                    for type in activity service provider receiver; do
            print_section "Checking exported $type components"
            ((manifest_checks++))
            exported_list=()
            while IFS=$'\t' read -r name exported; do
                
                if [[ "$exported" == "true" || -z "$exported" ]]; then
                    exported_list+=("$name (exported=${exported:-MISSING})")
                fi
            done < <(xmlstarlet sel -t -m "//$type" -v "@android:name" -o $'\t' -v "@android:exported" -n "$xml_file")

            if (( ${#exported_list[@]} > 0 )); then
                echo -e "${YELLOW}- Exported $type components found (explicit or implicit):${NC}"
                for item in "${exported_list[@]}"; do 
                    echo -e "${PURPLE}  - $item${NC}"
                done
                ((manifest_matches++))
            else
                echo -e "${GREEN}- No exported $type components found.${NC}"
            fi
        done

           print_section "Commencing Analysis on Application's Source code:"

            declare -A categories
            categories=(
                ["Storage & File Handling"]="DeviceId references|getDeviceId
External storage read|MODE_WORLD_READABLE
External storage write references|MODE_WORLD_WRITEABLE
Get External Storage|Environment.getExternalStorage
Accessing file output references|openFileOutput
Writing local file references|FileWriter
getSharedPreferences references|getSharedPreferences
getExternal references|getExternal
file:// references|file://"
                ["Networking & SSL"]="android.intent|android.intent
Intent|intent
Content Providers & urls|://
Service references|stopService|startService
Broadcast Receiver reference|BroadcastReceiver|onReceive|sendBroadcast
Host name Verifier|setHostnameVerifier
Trust Manager references|TrustManager
Check Server trusted|checkServerTrusted
Searching for URLs|http:|https:
HTTP headers|addHeader
UDP and TCP Sockets|.connect(|.disconnect|serverSocket|DatagramSocket
Client certificates|.pkcs|.p12|.cer|.der
SSL certificate pinning|getCertificatePinningSSL
SSL connections|ssl.SSL
WebView activity|WebView
addJavascriptInterface references|addJavascriptInterface
setJavaScriptEnabled references|setJavaScriptEnabled
setAllowFileAccess references|setAllow
setSavePassword references|setSavePassword"
                ["Cryptography"]="Crypto references|crypto.
MessageDigest references|MessageDigest
Weak Encryption & Hashing (MD5)|MessageDigest.getInstance(\"MD5\")
Weak Encryption & Hashing (SHA1)|MessageDigest.getInstance(\"SHA1\")
Weak Encryption & Hashing (AES)|Cipher.getInstance(\"AES/ECB\")
Weak Encryption & Hashing (DES)|DES/
Weak Encryption & Hashing (RC4)|RC4
Base64|Base64
Hex|Hex|hex."
                ["Code Execution & SQL"]="Command execution|Runtime.getRuntime().exec
SQLiteDatabase references|SQLiteDatabase
Usage of Raw SQL Query|rawQuery\\(
Usage of SQL Query|execSQL\\(
Process builder|ProcessBuilder\\("
                ["App Hardening & Secrets"]="Log.d|log.d|Log.
Debug Leaks|System.out.println
App hardening Secrets|API_KEY|SECRET|PASSWORD|ACCESS_TOKEN|Bearer|Basic|TODO|FIXME|DEBUG
Hardcoded secrets|secret|password|username
Sensitive information|user|pass|key|login|pwd|log"
            )

            src_path="$decompiled_filepath/decompiled_java/sources"
            findings_file="$decompiled_filepath/findings.txt"
            > "$findings_file"

            total_checks=0
            total_matches=0
            declare -A category_counts

            
            for category in "${!categories[@]}"; do
                print_section "$category"
                echo "==================== $category ====================" >> "$findings_file"
                IFS=$'\n' read -d '' -r -a checks <<< "${categories[$category]}"
                category_count=0
                for item in "${checks[@]}"; do
                    ((total_checks++))
                    desc=$(echo "$item" | cut -d'|' -f1)
                    pattern=$(echo "$item" | cut -d'|' -f2)
                    matches=$(grep -R -n -i -E "$pattern" "$src_path" 2>/dev/null)
                    if [[ -n "$matches" ]]; then
                        count=$(echo "$matches" | wc -l)
                        ((total_matches++))
                        ((category_count+=count))
                        echo -e "  ${RED}[!] $desc -> $count matches${NC}"
                        echo "---- $desc ----" >> "$findings_file"
                        echo "$matches" >> "$findings_file"
                        echo "" >> "$findings_file"
                    else
                        echo -e "  ${GREEN}[OK] $desc -> 0 matches${NC}"
                        echo "---- $desc ----" >> "$findings_file"
                        echo "No matches found" >> "$findings_file"
                        echo "" >> "$findings_file"
                    fi
                done
                category_counts["$category"]=$category_count
                echo "" >> "$findings_file"
            done

            print_section "Final Summary"
            echo -e "${BLUE} Manifest checks run   : $manifest_checks${NC}"
            echo -e "${BLUE} Manifest findings     : $manifest_matches${NC}"
            echo -e "${BLUE} Source checks run     : $total_checks${NC}"
            echo -e "${BLUE} Source matches found  : $total_matches${NC}"
            echo "------------------------------------------------"
            for category in "${!category_counts[@]}"; do
                echo -e "${CYAN} $category -> ${category_counts[$category]} matches${NC}"
            done
            echo "------------------------------------------------"
            echo -e "${GREEN} Detailed findings are available in: $findings_file${NC}"
            echo -e "${GREEN} Assessment Report is available in: $report_file${NC}"

            print_section "End of Report" 

            ;;
        u)
            url=$OPTARG
            echo -e "${BLUE}URL mode not implemented yet: $url${NC}"
            ;;
        h)
            echo -e "${YELLOW}Usage: $0 -d <apk_file> | -u <url> | -h${NC}"
            ;;
        *)
            echo -e "${RED}Invalid option. Use -h for help.${NC}"
            ;;
    esac
done
