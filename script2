#!/bin/bash
clear

# --- متغيرات اللغة الافتراضية والقاموس ---
declare -A translations

# تعريف الألوان (ANSI Escape Codes)
RED='\e[31m'    # أحمر (للتحذيرات والأخطاء والخيارات الخطيرة)
GREEN='\e[32m'  # أخضر (للخيارات الإيجابية، النجاح، وخيارات التنفيذ)
YELLOW='\e[33m' # أصفر (للمعلومات أو التنبيهات الخفيفة)
BLUE='\e[34m'   # أزرق (للعناوين أو التحديدات)
MAGENTA='\e[35m' # أرجواني
CYAN='\e[36m'   # سماوي (للعناوين الرئيسية)
NC='\e[0m'      # إرجاع اللون الأصلي (No Color)

# الإنجليزية (English)
translations[en,title_ascii_text]="NOVA TEAM Elite Toolkit"
translations[en,powered_by]="Powered by NOVA TEAM"
translations[en,root_privileges_required]="${RED}[!] This script requires root privileges. Please run with 'sudo'.${NC}"
translations[en,warning_title]="WARNING"
translations[en,warning_body_1]="This tool (NOVA TEAM Elite Toolkit) is intended solely for educational, research, and ethical hacking purposes."
translations[en,warning_body_2]="Unauthorized or illegal use of this tool will lead to legal consequences. The user bears full responsibility."
translations[en,warning_body_3]="Always ensure you have explicit, written permission before using this tool on any system you do not own or are not authorized to test."
translations[en,redirecting_message]="Redirecting to the main menu in"
translations[en,seconds]="seconds..."
translations[en,install_tools_section]="⬇️ INSTALLATION TOOLS"
translations[en,run_tools_section]="▶️ LAUNCH TOOLS"
translations[en,system_maintenance_section]="🧹 SYSTEM MAINTENANCE"
translations[en,contact_section]="📞 CONTACT US"
translations[en,exit_tool]="Exit Tool"
translations[en,enter_choice]="Enter your choice here 👉"
translations[en,invalid_option]="${RED}⚠️ Invalid option! Please choose a number or letter from the menu. Try again.${NC}"
translations[en,press_any_key]="${GREEN}🚀 Press any key to continue...${NC}"

# New/Modified Translations for "Install All" and Update Check
translations[en,check_updates_title]="SYSTEM & TOOLS UPDATE CHECK"
translations[en,check_updates_msg]="${YELLOW}[*] Checking for system and essential tools updates...${NC}"
translations[en,updates_found_prompt]="${YELLOW}[*] Updates are available or essential tools might be missing. Do you want to update/install all base requirements now? (y/N)${NC}"
translations[en,no_updates_needed]="${GREEN}[+] System and essential tools are up-to-date or requirements met.${NC}"
translations[en,update_started]="${GREEN}[+] Starting full system update and essential tools installation...${NC}"
translations[en,update_skipped]="${YELLOW}[*] Update skipped. Proceeding to main menu.${NC}"
translations[en,install_all_desc]="Install/Update All Tools (Full Suite)"
translations[en,install_all_confirm]="${YELLOW}[*] Are you sure you want to install/update ALL tools? This may take a long time and require significant disk space. (y/N)${NC}"
translations[en,install_all_starting]="${GREEN}[+] Starting full installation/update of all tools. Please be patient...${NC}"
translations[en,install_all_complete]="${GREEN}[+] All selected tools have been processed.${NC}"

# Global tool installation/launch messages
translations[en,update_system_desc]="Update System & Install Base Essentials"
translations[en,install_msg_start]="Installing"
translations[en,install_msg_end]="installed successfully."
translations[en,install_msg_failed]="${RED}Installation failed for${NC}"
translations[en,download_msg]="Downloading"
translations[en,extract_msg]="Extracting and installing"
translations[en,manual_install_info]="requires manual download and installation. Please visit:"
translations[en,manual_install_success]="${GREEN}Manual installation info provided.${NC}"
translations[en,system_update_fail]="${RED}System update failed. Check internet connection and repositories.${NC}"
translations[en,base_tools_fail]="${RED}Failed to install all base requirements. Some tools may not work.${NC}"
translations[en,sliver_download_fail]="${RED}Failed to download Sliver server. Check version or network.${NC}"
translations[en,sliver_client_download_fail]="${RED}Failed to download Sliver client. Check version or network.${NC}"
translations[en,ghost_clone_fail]="${RED}Failed to clone Ghost Framework repository.${NC}"
translations[en,dir_change_fail]="${RED}Failed to change directory to${NC}"
translations[en,ghost_install_fail]="${RED}Failed to install Ghost Framework. Review dependencies.${NC}"
translations[en,impacket_clone_fail]="${RED}Failed to clone Impacket repository.${NC}"
translations[en,impacket_install_fail]="${RED}Failed to install Impacket or its dependencies.${NC}"
translations[en,cme_install_fail]="${RED}Failed to install CrackMapExec. Ensure pipx is installed correctly.${NC}"
translations[en,empire_clone_fail]="${RED}Failed to clone Empire repository.${NC}"
translations[en,empire_install_info]="${YELLOW}After installation, you must run 'sudo python3 ./empire' in the Empire directory.${NC}"
translations[en,starkiller_info]="${YELLOW}To install Starkiller (GUI), visit: https://github.com/BC-SECURITY/Starkiller/releases${NC}"
translations[en,cleanup_start]="${YELLOW}[*] Cleaning system...${NC}"
translations[en,cleanup_complete]="${GREEN}[+] System cleanup complete.${NC}"
translations[en,exit_success]="${GREEN}Exited NOVA TEAM Elite Toolkit successfully. Goodbye!${NC}"
translations[en,contact_discord]="Discord: N-T" # Added Discord contact

# Category names
translations[en,cat_c2_rat_post]="🧠 C2 / RAT / Post Exploitation"
translations[en,cat_mitm_sniffing]="🌐 MITM & Sniffing Tools"
translations[en,cat_windows_ad_exploit]="💻 Windows / Active Directory Exploitation"
translations[en,cat_android_mobile]="📱 Android / Mobile Exploitation"
translations[en,cat_password_attacks]="🔐 Password Attacks / Hashing / Cracking"
translations[en,cat_wifi_wireless]="🛜 Wi-Fi / Wireless Attacks"
translations[en,cat_web_exploitation]="🕳️ Web & Exploitation Tools"
translations[en,cat_privacy_anonymity]="👻 Privacy / Anonymity / Evasion"
translations[en,cat_useful_utilities]="⚙️ Others - Useful Utilities"
translations[en,back_to_main_menu]="Back to Main Menu"
translations[en,back_to_prev_menu]="Back to Previous Menu"

# Specific tool translations - INSTALL
translations[en,install_msf_desc]="Install Metasploit Framework"
translations[en,install_empire_desc]="Install Empire C2"
translations[en,install_pupy_desc]="Install Pupy"
translations[en,install_sliver_desc]="Install Sliver C2"
translations[en,install_covenant_desc]="Install Covenant C2"
translations[en,install_quasarrat_desc]="Install QuasarRAT"
translations[en,install_bettercap_desc]="Install Bettercap"
translations[en,install_ettercap_desc]="Install Ettercap"
translations[en,install_evilginx2_desc]="Install Evilginx2"
translations[en,install_wireshark_desc]="Install Wireshark"
translations[en,install_mitmf_desc]="Install MITMf (Man-in-the-Middle Framework)"
translations[en,install_fruitywifi_desc]="Install FruityWiFi"
translations[en,install_cme_desc]="Install CrackMapExec (CME)"
translations[en,install_bloodhound_desc]="Install BloodHound"
translations[en,install_sharphound_desc]="Install SharpHound (Collector for BloodHound)"
translations[en,install_mimikatz_desc]="Install Mimikatz (Windows binary)"
translations[en,install_impacket_desc]="Install Impacket"
translations[en,install_responder_desc]="Install Responder"
translations[en,install_kerbrute_desc]="Install Kerbrute"
translations[en,install_rpcclient_smbclient_desc]="Install rpcclient / smbclient"
translations[en,install_ghost_desc]="Install Ghost Framework"
translations[en,install_evildroid_desc]="Install Evil-Droid"
translations[en,install_ahmyth_desc]="Install AhMyth"
translations[en,install_mobsf_desc]="Install MobSF (Mobile Security Framework)"
translations[en,install_androrat_desc]="Install AndroRAT"
translations[en,install_john_desc]="Install John the Ripper"
translations[en,install_hashcat_desc]="Install Hashcat"
translations[en,install_hydra_desc]="Install Hydra"
translations[en,install_medusa_desc]="Install Medusa"
translations[en,install_seclists_desc]="Install SecLists (Wordlists Collection)"
translations[en,install_crunch_desc]="Install Crunch (Wordlist Generator)"
translations[en,install_aircrackng_desc]="Install Aircrack-ng"
translations[en,install_wifite2_desc]="Install Wifite2"
translations[en,install_kismet_desc]="Install Kismet"
translations[en,install_reaver_desc]="Install Reaver"
translations[en,install_pixiewps_desc]="Install PixieWPS"
translations[en,install_wifiphisher_desc]="Install Wifiphisher"
translations[en,install_sqlmap_desc]="Install SQLMap"
translations[en,install_xsser_desc]="Install XSSer"
translations[en,install_xsstrike_desc]="Install XSStrike"
translations[en,install_nikto_desc]="Install Nikto"
translations[en,install_dirb_dirbuster_desc]="Install Dirb / Dirbuster"
translations[en,install_gobuster_desc]="Install Gobuster"
translations[en,install_wfuzz_desc]="Install WFuzz"
translations[en,install_nipe_desc]="Install Nipe (Tor for Kali)"
translations[en,install_tor_desc]="Install Tor (Anonymity Network)"
translations[en,install_macchanger_desc]="Install Macchanger"
translations[en,install_proxychains_desc]="Install Proxychains"
translations[en,install_chameleon_desc]="Install Chameleon (Obfuscation)"
translations[en,install_netcat_desc]="Install Netcat (nc)"
translations[en,install_nmap_desc]="Install Nmap"
translations[en,install_tcpdump_desc]="Install tcpdump"
translations[en,install_httrack_desc]="Install HTTrack (Website Copier)"
translations[en,install_binwalk_desc]="Install Binwalk (Firmware Analysis)"
translations[en,install_exiftool_desc]="Install ExifTool (Metadata Analyzer)"
translations[en,install_ghidra_desc]="Install Ghidra (Manual)"
translations[en,install_burpsuite_desc]="Install Burp Suite Community (Manual)"

# Specific tool translations - LAUNCH
translations[en,launch_msf_desc]="Launch Metasploit Console (msfconsole)"
translations[en,launch_empire_desc]="Launch Empire C2 (Run setup/empire manually first!)"
translations[en,launch_pupy_desc]="Launch Pupy (Manual launch/setup)"
translations[en,launch_sliver_server_desc]="Launch Sliver Server (sliver-server)"
translations[en,launch_sliver_client_desc]="Launch Sliver Client (sliver-client)"
translations[en,launch_covenant_desc]="Launch Covenant (Docker/Manual launch)"
translations[en,launch_quasarrat_desc]="Launch QuasarRAT (Manual build/launch)"
translations[en,launch_bettercap_desc]="Launch Bettercap (e.g., sudo bettercap -iface wlan0)"
translations[en,launch_ettercap_desc]="Launch Ettercap (sudo ettercap -G)"
translations[en,launch_evilginx2_desc]="Launch Evilginx2 (Manual setup/config)"
translations[en,launch_wireshark_desc]="Launch Wireshark (sudo wireshark &)"
translations[en,launch_mitmf_desc]="Launch MITMf (Manual setup/run)"
translations[en,launch_fruitywifi_desc]="Launch FruityWiFi (Manual setup/config)"
translations[en,launch_cme_desc]="Launch CrackMapExec (e.g., cme smb [TargetIPs])"
translations[en,launch_bloodhound_desc]="Launch BloodHound (neo4j and BloodHound.py/SharpHound)"
translations[en,launch_sharphound_desc]="SharpHound (Collector for BloodHound - Requires .NET)"
translations[en,launch_mimikatz_desc]="Mimikatz (Windows binary - Run on Windows target)"
translations[en,launch_impacket_desc]="Launch Impacket tools (e.g., impacket-smbclient)"
translations[en,launch_responder_desc]="Launch Responder (e.g., sudo responder -i eth0 -rv)"
translations[en,launch_kerbrute_desc]="Launch Kerbrute (e.g., kerbrute userenum --domain example.com users.txt)"
translations[en,launch_rpcclient_desc]="Launch rpcclient (e.g., rpcclient -U user%pass //target)"
translations[en,launch_smbclient_desc]="Launch smbclient (e.g., smbclient //target/share -U user%pass)"
translations[en,launch_ghost_desc]="Launch Ghost Framework (/opt/ghost/ghost)"
translations[en,launch_evildroid_desc]="Launch Evil-Droid (Manual setup/script)"
translations[en,launch_ahmyth_desc]="Launch AhMyth (Manual setup/server)"
translations[en,launch_mobsf_desc]="Launch MobSF (Manual setup/server)"
translations[en,launch_androrat_desc]="Launch AndroRAT (Manual build/server)"
translations[en,launch_john_desc]="Launch John the Ripper (e.g., john --wordlist=passwords.txt hash.txt)"
translations[en,launch_hashcat_desc]="Launch Hashcat (e.g., hashcat -m 0 -a 0 hash.txt dict.txt)"
translations[en,launch_hydra_desc]="Launch Hydra (e.g., hydra -L users.txt -P pass.txt [TargetIP] ssh)"
translations[en,launch_medusa_desc]="Launch Medusa (e.g., medusa -h [TargetIP] -u user -P pass.txt -M ssh)"
translations[en,launch_seclists_desc]="SecLists are installed in /usr/share/seclists or /opt/SecLists."
translations[en,launch_crunch_desc]="Launch Crunch (e.g., crunch 4 4 -o output.txt -t @@@@)"
translations[en,launch_aircrackng_desc]="Launch Aircrack-ng (e.g., aircrack-ng -b [BSSID] capture.cap)"
translations[en,launch_wifite2_desc]="Launch Wifite2 (e.g., wifite --show-ifaces)"
translations[en,launch_kismet_desc]="Launch Kismet (sudo kismet)"
translations[en,launch_reaver_desc]="Launch Reaver (e.g., reaver -i wlan0mon -b [BSSID] -vv)"
translations[en,launch_pixiewps_desc]="Launch PixieWPS (e.g., pixiewps -i wlan0mon -b [BSSID] -a -r [router_pin])"
translations[en,launch_wifiphisher_desc]="Launch Wifiphisher (sudo wifiphisher)"
translations[en,launch_sqlmap_desc]="Launch SQLMap (e.g., sqlmap -u [TargetURL] --dbs)"
translations[en,launch_xsser_desc]="Launch XSSer (e.g., xsser -u [TargetURL] -g \"<script>alert(1)</script>\")"
translations[en,launch_xsstrike_desc]="Launch XSStrike (e.g., xsstrike -u [TargetURL])"
translations[en,launch_nikto_desc]="Launch Nikto (e.g., nikto -h [TargetURL])"
translations[en,launch_dirb_desc]="Launch Dirb (e.g., dirb http://example.com /usr/share/wordlists/dirb/common.txt)"
translations[en,launch_dirbuster_desc]="Launch Dirbuster (Java GUI - Manual)"
translations[en,launch_gobuster_desc]="Launch Gobuster (e.g., gobuster dir -u http://example.com -w /path/to/wordlist.txt)"
translations[en,launch_wfuzz_desc]="Launch WFuzz (e.g., wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt --hc 404 http://example.com/FUZZ)"
translations[en,launch_nipe_desc]="Launch Nipe (start/stop/restart: sudo nipe start)"
translations[en,launch_tor_desc]="Launch Tor (service tor start)"
translations[en,launch_macchanger_desc]="Launch Macchanger (e.g., sudo macchanger -r eth0)"
translations[en,launch_proxychains_desc]="Launch Proxychains (e.g., proxychains nmap -sT [TargetIP])"
translations[en,launch_chameleon_desc]="Launch Chameleon (Manual usage)"
translations[en,launch_netcat_desc]="Launch Netcat (e.g., nc -lvnp 4444)"
translations[en,launch_nmap_desc]="Launch Nmap (e.g., nmap -sV -sC [TargetIP])"
translations[en,launch_tcpdump_desc]="Launch tcpdump (e.g., sudo tcpdump -i eth0)"
translations[en,launch_httrack_desc]="Launch HTTrack (Website Copier)"
translations[en,launch_binwalk_desc]="Launch Binwalk (Firmware Analysis)"
translations[en,launch_exiftool_desc]="Launch ExifTool (Metadata Analyzer)"
translations[en,launch_ghidra_desc]="Launch Ghidra (Manual, run from its directory)"
translations[en,launch_burpsuite_desc]="Launch Burp Suite (Manual, run from its directory)"

# العربية (Arabic)
translations[ar,title_ascii_text]="أدوات نوفا تيم النخبة"
translations[ar,powered_by]="برعاية نوفا تيم"
translations[ar,root_privileges_required]="${RED}[!] هذا السكربت يتطلب صلاحيات الروت. يرجى التشغيل باستخدام 'sudo'.${NC}"
translations[ar,warning_title]="تحذير"
translations[ar,warning_body_1]="هذه الأداة (NOVA TEAM Elite Toolkit) مخصصة فقط للأغراض التعليمية، البحثية، واختبار الاختراق الأخلاقي (Ethical Hacking)."
translations[ar,warning_body_2]="الاستخدام غير المصرح به أو غير القانوني لهذه الأداة يعرضك للمساءلة القانونية ويتحمل المستخدم وحده مسؤوليته الكاملة."
translations[ar,warning_body_3]="تأكد دائمًا من حصولك على إذن صريح ومكتوب قبل استخدام هذه الأداة على أي نظام لا تملكه أو ليس لديك تصريح لاختباره."
translations[ar,redirecting_message]="سيتم الانتقال إلى القائمة الرئيسية خلال"
translations[ar,seconds]="ثانية..."
translations[ar,install_tools_section]="⬇️ أدوات التثبيت"
translations[ar,run_tools_section]="▶️ أدوات التشغيل"
translations[ar,system_maintenance_section]="🧹 صيانة النظام"
translations[ar,contact_section]="📞 تواصل معنا"
translations[ar,exit_tool]="خروج من الأداة"
translations[ar,enter_choice]="أدخل اختيارك هنا 👉"
translations[ar,invalid_option]="${RED}⚠️ خيار غير صحيح! يرجى اختيار رقم أو حرف من القائمة. حاول مرة أخرى.${NC}"
translations[ar,press_any_key]="${GREEN}🚀 اضغط على أي مفتاح للمتابعة...${NC}"

# New/Modified Translations for "Install All" and Update Check
translations[ar,check_updates_title]="التحقق من تحديثات النظام والأدوات"
translations[ar,check_updates_msg]="${YELLOW}[*] جارٍ التحقق من تحديثات النظام والأدوات الأساسية...${NC}"
translations[ar,updates_found_prompt]="${YELLOW}[*] تتوفر تحديثات أو قد تكون بعض الأدوات الأساسية مفقودة. هل ترغب في تحديث/تثبيت جميع المتطلبات الأساسية الآن؟ (ن/ل)${NC}"
translations[ar,no_updates_needed]="${GREEN}[+] النظام والأدوات الأساسية محدثة أو المتطلبات متوفرة.${NC}"
translations[ar,update_started]="${GREEN}[+] جارٍ بدء تحديث النظام بالكامل وتثبيت الأدوات الأساسية...${NC}"
translations[ar,update_skipped]="${YELLOW}[*] تم تخطي التحديث. جارٍ الانتقال إلى القائمة الرئيسية.${NC}"
translations[ar,install_all_desc]="تثبيت/تحديث جميع الأدوات (الحزمة الكاملة)"
translations[ar,install_all_confirm]="${YELLOW}[*] هل أنت متأكد أنك تريد تثبيت/تحديث جميع الأدوات؟ قد يستغرق هذا وقتًا طويلاً ويتطلب مساحة قرص كبيرة. (ن/ل)${NC}"
translations[ar,install_all_starting]="${GREEN}[+] جارٍ بدء التثبيت/التحديث الكامل لجميع الأدوات. يرجى التحلي بالصبر...${NC}"
translations[ar,install_all_complete]="${GREEN}[+] تم معالجة جميع الأدوات المختارة.${NC}"

# Global tool installation/launch messages
translations[ar,update_system_desc]="تحديث النظام وتثبيت الأساسيات"
translations[ar,install_msg_start]="جارٍ تثبيت"
translations[ar,install_msg_end]="تم التثبيت بنجاح."
translations[ar,install_msg_failed]="${RED}فشل تثبيت${NC}"
translations[ar,download_msg]="جارٍ تنزيل"
translations[ar,extract_msg]="جارٍ فك الضغط والتثبيت"
translations[ar,manual_install_info]="تتطلب تنزيلًا يدويًا وتثبيتًا. يرجى زيارة:"
translations[ar,manual_install_success]="${GREEN}تم توفير معلومات التثبيت اليدوي.${NC}"
translations[ar,system_update_fail]="${RED}فشل تحديث النظام. يرجى التحقق من اتصالك بالإنترنت ومستودعات البرامج.${NC}"
translations[ar,base_tools_fail]="${RED}فشل تثبيت جميع المتطلبات الأساسية. قد لا تعمل بعض الأدوات بشكل صحيح.${NC}"
translations[ar,sliver_download_fail]="${RED}فشل تنزيل خادم Sliver. تحقق من الإصدار أو شبكة الإنترنت.${NC}"
translations[ar,sliver_client_download_fail]="${RED}فشل تنزيل عميل Sliver. تحقق من الإصدار أو شبكة الإنترنت.${NC}"
translations[ar,ghost_clone_fail]="${RED}فشل استنساخ مستودع Ghost Framework.${NC}"
translations[ar,dir_change_fail]="${RED}فشل الانتقال إلى الدليل${NC}"
translations[ar,ghost_install_fail]="${RED}فشل تثبيت Ghost Framework. يرجى مراجعة تبعياته.${NC}"
translations[ar,impacket_clone_fail]="${RED}فشل استنساخ مستودع Impacket.${NC}"
translations[ar,impacket_install_fail]="${RED}فشل تثبيت Impacket أو تبعياته.${NC}"
translations[ar,cme_install_fail]="${RED}فشل تثبيت CrackMapExec. تأكد من أن pipx مثبت بشكل صحيح.${NC}"
translations[ar,empire_clone_fail]="${RED}فشل استنساخ مستودع Empire.${NC}"
translations[ar,empire_install_info]="${YELLOW}بعد التثبيت، يجب عليك تشغيل 'sudo python3 ./empire' في دليل Empire.${NC}"
translations[ar,starkiller_info]="${YELLOW}لتثبيت Starkiller (الواجهة الرسومية)، يرجى زيارة: https://github.com/BC-SECURITY/Starkiller/releases${NC}"
translations[ar,cleanup_start]="${YELLOW}[*] جارٍ تنظيف النظام...${NC}"
translations[ar,cleanup_complete]="${GREEN}[+] اكتمل تنظيف النظام.${NC}"
translations[ar,exit_success]="${GREEN}تم الخروج بنجاح من NOVA TEAM Elite Toolkit. إلى اللقاء!${NC}"
translations[ar,contact_discord]="ديسكورد: N-T"

# Category names
translations[ar,cat_c2_rat_post]="🧠 أدوات C2 / RAT / ما بعد الاختراق"
translations[ar,cat_mitm_sniffing]="🌐 أدوات هجمات الوسيط والتنصت"
translations[ar,cat_windows_ad_exploit]="💻 استغلال أنظمة Windows / Active Directory"
translations[ar,cat_android_mobile]="📱 استغلال أنظمة Android / الأجهزة المحمولة"
translations[ar,cat_password_attacks]="🔐 هجمات كلمات المرور / التجزئة / الكسر"
translations[ar,cat_wifi_wireless]="🛜 هجمات Wi-Fi / اللاسلكي"
translations[ar,cat_web_exploitation]="🕳️ أدوات الويب والاستغلال"
translations[ar,cat_privacy_anonymity]="👻 الخصوصية / عدم الكشف عن الهوية / التخفي"
translations[ar,cat_useful_utilities]="⚙️ أدوات مساعدة أخرى"
translations[ar,back_to_main_menu]="العودة إلى القائمة الرئيسية"
translations[ar,back_to_prev_menu]="العودة إلى القائمة السابقة"

# Specific tool translations - INSTALL
translations[ar,install_msf_desc]="تثبيت Metasploit Framework"
translations[ar,install_empire_desc]="تثبيت Empire C2"
translations[ar,install_pupy_desc]="تثبيت Pupy"
translations[ar,install_sliver_desc]="تثبيت Sliver C2"
translations[ar,install_covenant_desc]="تثبيت Covenant C2"
translations[ar,install_quasarrat_desc]="تثبيت QuasarRAT"
translations[ar,install_bettercap_desc]="تثبيت Bettercap"
translations[ar,install_ettercap_desc]="تثبيت Ettercap"
translations[ar,install_evilginx2_desc]="تثبيت Evilginx2"
translations[ar,install_wireshark_desc]="تثبيت Wireshark"
translations[ar,install_mitmf_desc]="تثبيت MITMf (Man-in-the-Middle Framework)"
translations[ar,install_fruitywifi_desc]="تثبيت FruityWiFi"
translations[ar,install_cme_desc]="تثبيت CrackMapExec (CME)"
translations[ar,install_bloodhound_desc]="تثبيت BloodHound"
translations[ar,install_sharphound_desc]="تثبيت SharpHound (جامع بيانات لـ BloodHound)"
translations[ar,install_mimikatz_desc]="تثبيت Mimikatz (ملف تنفيذي للويندوز)"
translations[ar,install_impacket_desc]="تثبيت Impacket"
translations[ar,install_responder_desc]="تثبيت Responder"
translations[ar,install_kerbrute_desc]="تثبيت Kerbrute"
translations[ar,install_rpcclient_smbclient_desc]="تثبيت rpcclient / smbclient"
translations[ar,install_ghost_desc]="تثبيت Ghost Framework"
translations[ar,install_evildroid_desc]="تثبيت Evil-Droid"
translations[ar,install_ahmyth_desc]="تثبيت AhMyth"
translations[ar,install_mobsf_desc]="تثبيت MobSF (Mobile Security Framework)"
translations[ar,install_androrat_desc]="تثبيت AndroRAT"
translations[ar,install_john_desc]="تثبيت John the Ripper"
translations[ar,install_hashcat_desc]="تثبيت Hashcat"
translations[ar,install_hydra_desc]="تثبيت Hydra"
translations[ar,install_medusa_desc]="تثبيت Medusa"
translations[ar,install_seclists_desc]="تثبيت SecLists (مجموعة قوائم كلمات)"
translations[ar,install_crunch_desc]="تثبيت Crunch (مولد قوائم كلمات)"
translations[ar,install_aircrackng_desc]="تثبيت Aircrack-ng"
translations[ar,install_wifite2_desc]="تثبيت Wifite2"
translations[ar,install_kismet_desc]="تثبيت Kismet"
translations[ar,install_reaver_desc]="تثبيت Reaver"
translations[ar,install_pixiewps_desc]="تثبيت PixieWPS"
translations[ar,install_wifiphisher_desc]="تثبيت Wifiphisher"
translations[ar,install_sqlmap_desc]="تثبيت SQLMap"
translations[ar,install_xsser_desc]="تثبيت XSSer"
translations[ar,install_xsstrike_desc]="تثبيت XSStrike"
translations[ar,install_nikto_desc]="تثبيت Nikto"
translations[ar,install_dirb_dirbuster_desc]="تثبيت Dirb / Dirbuster"
translations[ar,install_gobuster_desc]="تثبيت Gobuster"
translations[ar,install_wfuzz_desc]="تثبيت WFuzz"
translations[ar,install_nipe_desc]="تثبيت Nipe (Tor لـ Kali)"
translations[ar,install_tor_desc]="تثبيت Tor (شبكة إخفاء الهوية)"
translations[ar,install_macchanger_desc]="تثبيت Macchanger"
translations[ar,install_proxychains_desc]="تثبيت Proxychains"
translations[ar,install_chameleon_desc]="تثبيت Chameleon (تخفي)"
translations[ar,install_netcat_desc]="تثبيت Netcat (nc)"
translations[ar,install_nmap_desc]="تثبيت Nmap"
translations[ar,install_tcpdump_desc]="تثبيت tcpdump"
translations[ar,install_httrack_desc]="تثبيت HTTrack (ناسخ مواقع الويب)"
translations[ar,install_binwalk_desc]="تثبيت Binwalk (تحليل البرامج الثابتة)"
translations[ar,install_exiftool_desc]="تثبيت ExifTool (محلل البيانات الوصفية)"
translations[ar,install_ghidra_desc]="تثبيت Ghidra (يدوي)"
translations[ar,install_burpsuite_desc]="تثبيت Burp Suite Community (يدوي)"

# Specific tool translations - LAUNCH
translations[ar,launch_msf_desc]="تشغيل Metasploit Console (msfconsole)"
translations[ar,launch_empire_desc]="تشغيل Empire C2 (يجب تشغيل الإعدادات يدوياً أولاً!)"
translations[ar,launch_pupy_desc]="تشغيل Pupy (تشغيل/إعداد يدوي)"
translations[ar,launch_sliver_server_desc]="تشغيل Sliver Server (sliver-server)"
translations[ar,launch_sliver_client_desc]="تشغيل Sliver Client (sliver-client)"
translations[ar,launch_covenant_desc]="تشغيل Covenant (عبر Docker/تشغيل يدوي)"
translations[ar,launch_quasarrat_desc]="تشغيل QuasarRAT (بناء/تشغيل يدوي)"
translations[ar,launch_bettercap_desc]="تشغيل Bettercap (مثال: sudo bettercap -iface wlan0)"
translations[ar,launch_ettercap_desc]="تشغيل Ettercap (sudo ettercap -G)"
translations[ar,launch_evilginx2_desc]="تشغيل Evilginx2 (إعداد/تكوين يدوي)"
translations[ar,launch_wireshark_desc]="تشغيل Wireshark (sudo wireshark &)"
translations[ar,launch_mitmf_desc]="تشغيل MITMf (إعداد/تشغيل يدوي)"
translations[ar,launch_fruitywifi_desc]="تشغيل FruityWiFi (إعداد/تكوين يدوي)"
translations[ar,launch_cme_desc]="تشغيل CrackMapExec (مثال: cme smb [TargetIPs])"
translations[ar,launch_bloodhound_desc]="تشغيل BloodHound (يتطلب neo4j و BloodHound.py/SharpHound)"
translations[ar,launch_sharphound_desc]="SharpHound (جامع بيانات لـ BloodHound - يتطلب .NET)"
translations[ar,launch_mimikatz_desc]="Mimikatz (ملف تنفيذي للويندوز - يعمل على أهداف ويندوز)"
translations[ar,launch_impacket_desc]="تشغيل أدوات Impacket (مثال: impacket-smbclient)"
translations[ar,launch_responder_desc]="تشغيل Responder (مثال: sudo responder -i eth0 -rv)"
translations[ar,launch_kerbrute_desc]="تشغيل Kerbrute (مثال: kerbrute userenum --domain example.com users.txt)"
translations[ar,launch_rpcclient_desc]="تشغيل rpcclient (مثال: rpcclient -U user%pass //هدف)"
translations[ar,launch_smbclient_desc]="تشغيل smbclient (مثال: smbclient //هدف/مشاركة -U user%pass)"
translations[ar,launch_ghost_desc]="تشغيل Ghost Framework (/opt/ghost/ghost)"
translations[ar,launch_evildroid_desc]="تشغيل Evil-Droid (إعداد/سكربت يدوي)"
translations[ar,launch_ahmyth_desc]="تشغيل AhMyth (إعداد/سيرفر يدوي)"
translations[ar,launch_mobsf_desc]="تشغيل MobSF (إعداد/سيرفر يدوي)"
translations[ar,launch_androrat_desc]="تشغيل AndroRAT (بناء/سيرفر يدوي)"
translations[ar,launch_john_desc]="تشغيل John the Ripper (مثال: john --wordlist=passwords.txt hash.txt)"
translations[ar,launch_hashcat_desc]="تشغيل Hashcat (مثال: hashcat -m 0 -a 0 hash.txt dict.txt)"
translations[ar,launch_hydra_desc]="تشغيل Hydra (مثال: hydra -L users.txt -P pass.txt [TargetIP] ssh)"
translations[ar,launch_medusa_desc]="تشغيل Medusa (مثال: medusa -h [TargetIP] -u user -P pass.txt -M ssh)"
translations[ar,launch_seclists_desc]="SecLists مثبتة في /usr/share/seclists أو /opt/SecLists."
translations[ar,launch_crunch_desc]="تشغيل Crunch (مثال: crunch 4 4 -o output.txt -t @@@@)"
translations[ar,launch_aircrackng_desc]="تشغيل Aircrack-ng (مثال: aircrack-ng -b [BSSID] capture.cap)"
translations[ar,launch_wifite2_desc]="تشغيل Wifite2 (مثال: wifite --show-ifaces)"
translations[ar,launch_kismet_desc]="تشغيل Kismet (sudo kismet)"
translations[ar,launch_reaver_desc]="تشغيل Reaver (مثال: reaver -i wlan0mon -b [BSSID] -vv)"
translations[ar,launch_pixiewps_desc]="تشغيل PixieWPS (مثال: pixiewps -i wlan0mon -b [BSSID] -a -r [router_pin])"
translations[ar,launch_wifiphisher_desc]="تشغيل Wifiphisher (sudo wifiphisher)"
translations[ar,launch_sqlmap_desc]="تشغيل SQLMap (مثال: sqlmap -u [TargetURL] --dbs)"
translations[ar,launch_xsser_desc]="تشغيل XSSer (مثال: xsser -u [TargetURL] -g \"<script>alert(1)</script>\")"
translations[ar,launch_xsstrike_desc]="تشغيل XSStrike (مثال: xsstrike -u [TargetURL])"
translations[ar,launch_nikto_desc]="تشغيل Nikto (مثال: nikto -h [TargetURL])"
translations[ar,launch_dirb_desc]="تشغيل Dirb (مثال: dirb http://example.com /usr/share/wordlists/dirb/common.txt)"
translations[ar,launch_dirbuster_desc]="تشغيل Dirbuster (واجهة Java الرسومية - يدوي)"
translations[ar,launch_gobuster_desc]="تشغيل Gobuster (مثال: gobuster dir -u http://example.com -w /path/to/wordlist.txt)"
translations[ar,launch_wfuzz_desc]="تشغيل WFuzz (مثال: wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt --hc 404 http://example.com/FUZZ)"
translations[ar,launch_nipe_desc]="تشغيل Nipe (بدء/إيقاف/إعادة تشغيل: sudo nipe start)"
translations[ar,launch_tor_desc]="تشغيل Tor (service tor start)"
translations[ar,launch_macchanger_desc]="تشغيل Macchanger (مثال: sudo macchanger -r eth0)"
translations[ar,launch_proxychains_desc]="تشغيل Proxychains (مثال: proxychains nmap -sT [TargetIP])"
translations[ar,launch_chameleon_desc]="تشغيل Chameleon (استخدام يدوي)"
translations[ar,launch_netcat_desc]="تشغيل Netcat (مثال: nc -lvnp 4444)"
translations[ar,launch_nmap_desc]="تشغيل Nmap (مثال: nmap -sV -sC [TargetIP])"
translations[ar,launch_tcpdump_desc]="تشغيل tcpdump (مثال: sudo tcpdump -i eth0)"
translations[ar,launch_httrack_desc]="تشغيل HTTrack (ناسخ مواقع الويب)"
translations[ar,launch_binwalk_desc]="تشغيل Binwalk (تحليل البرامج الثابتة)"
translations[ar,launch_exiftool_desc]="تشغيل ExifTool (محلل البيانات الوصفية)"
translations[ar,launch_ghidra_desc]="تشغيل Ghidra (يدوي، تشغيل من دليله)"
translations[ar,launch_burpsuite_desc]="تشغيل Burp Suite (يدوي، تشغيل من دليله)"


# اللغة الحالية (افتراضي English)
current_lang="en"

# دالة للحصول على الترجمة
_() {
  local key="$1"
  echo "${translations[${current_lang},${key}]}"
}

# --- بداية السكربت ---

# عنوان السكربت ورسم ASCII
echo -e "${RED}" # أحمر
echo "    _           _    _ ____ ____ ____ _  _ ____ "
echo "   / \   _ __ | |__| |___ |___ |__| |\ | |___ "
echo "  / _ \ | '_ \| / _\` |___ |___ |  | | \| | |___ "
echo " / ___ \| | | | | (_| |                                 "
echo "/_/   \_\_| |_|_|\__,_|                                 "
echo -e "${GREEN}" # أخضر
echo " ____ ____ _  _ ____    _    _   _ _  _ ___  _ ____ "
echo "|__| |___ |\/| |___    |    |   | |  | |  \ | | ___ "
echo "|  | |___ |  | |___    |___ |_ _| |__| |__/ | |___ "
echo -e "${NC}" # إرجاع اللون الأصلي

echo -e "${CYAN}[+] NOVA TEAM Elite Toolkit V999 | $(_ powered_by)${NC}"
sleep 1

# التحقق من صلاحيات الروت
if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}[!] ${translations[${current_lang},root_privileges_required]}${NC}"
  exit 1
fi

# دالة لعرض الرسائل الملونة (تم تعديلها لاستخدام المتغيرات)
display_message() {
  local type=$1
  local message=$2
  case $type in
    "info")    echo -e "${YELLOW}[*] ${message}${NC}" ;; # أصفر للمعلومات
    "success") echo -e "${GREEN}[+] ${message}${NC}" ;; # أخضر للنجاح
    "error")   echo -e "${RED}[!] ${message}${NC}" ;; # أحمر للأخطاء
  esac
}

# --- دالة لعرض النص بخط كبير باستخدام figlet / toilet ---
display_large_text() {
    local text="$1"
    local color_code="$2"
    echo -e "${color_code}"
    if command -v toilet &> /dev/null; then
        toilet --filter border -f term -- "$text"
    elif command -v figlet &> /dev/null; then
        figlet -f standard "$text"
    else
        echo "$text" # Fallback if neither is installed
    fi
    echo -e "${NC}" # إرجاع اللون الأصلي
}

# --- قائمة اختيار اللغة ---
choose_language() {
  clear
  echo -e "${CYAN}==================================================${NC}"
  echo -e "${GREEN}      Choose Your Language | اختر لغتك          ${NC}"
  echo -e "${CYAN}==================================================${NC}"
  echo -e "${YELLOW}"
  echo "  [1] English"
  echo "  [2] العربية"
  echo -e "${NC}"
  echo -n -e "${BLUE}Enter your choice / أدخل اختيارك: ${NC}"
  read -r lang_choice

  case $lang_choice in
    1) current_lang="en" ;;
    2) current_lang="ar" ;;
    *)
      echo -e "${RED}Invalid choice! Defaulting to English. / خيار غير صحيح! سيتم استخدام اللغة الإنجليزية.${NC}"
      current_lang="en"
      sleep 2
      ;;
  esac
  clear
}

# --- تحذير الاستخدام الأخلاقي (متعدد اللغات) ---
show_ethical_warning() {
  clear
  echo -e "${RED}" # لون أحمر للحدود
  echo "=================================================================="
  display_large_text "$(_ warning_title)" "${RED}" # تحذير بخط كبير
  echo "=================================================================="
  echo -e "${YELLOW}" # لون أصفر للنص

  echo "  $(_ warning_body_1)"
  echo ""
  echo "  ${RED}⚠️  $(_ warning_body_2)${NC}" # تحذير بلون أحمر قوي
  echo ""
  echo "  $(_ warning_body_3)"
  echo ""
  echo -e "${GREEN}  >>> $(_ redirecting_message) 15 $(_ seconds)${NC}"
  echo -e "${RED}" # لون أحمر للحدود السفلية
  echo "=================================================================="
  echo -e "${NC}"
  sleep 15 # الانتظار لمدة 15 ثانية
}
# -----------------------------------------------

# --- الدوال الخاصة بالتثبيت ---
# دالة عامة لتثبيت الأدوات باستخدام apt
install_apt_tool() {
  local tool_name="$1"
  local package_name="$2"
  display_message "info" "$(_ install_msg_start) ${tool_name}..."
  sudo apt install -y "${package_name}" &> /dev/null # أخفي الإخراج لجعل التثبيت أنظف
  if [[ $? -ne 0 ]]; then
    display_message "error" "$(_ install_msg_failed) ${tool_name}. Check internet connection or package name."
    return 1
  else
    display_message "success" "$(_ install_msg_end) ${tool_name}."
    return 0
  fi
}

# دالة عامة لتثبيت الأدوات باستخدام git clone
install_git_tool() {
    local tool_name="$1"
    local repo_url="$2"
    local install_dir="$3"
    display_message "info" "$(_ download_msg) ${tool_name}..."

    if [ -d "$install_dir" ]; then
        display_message "info" "${tool_name} already exists. Pulling latest changes..."
        (cd "$install_dir" && sudo git pull)
        if [[ $? -ne 0 ]]; then
            display_message "error" "Failed to update ${tool_name}."
            return 1
        fi
    else
        sudo git clone "$repo_url" "$install_dir"
        if [[ $? -ne 0 ]]; then
            display_message "error" "Failed to clone ${tool_name} repository."
            return 1
        fi
    fi
    display_message "success" "$(_ install_msg_end) ${tool_name} (cloned to ${install_dir})."
    return 0
}


# ----------------------------------------------------
# FUNCTIONS FOR EACH TOOL INSTALLATION (EXAMPLE, YOU NEED TO FILL THESE)
# ----------------------------------------------------

install_metasploit() {
    display_message "info" "$(_ install_msg_start) Metasploit Framework..."
    # Metasploit installation is complex, often involves curl and apt-get.
    # This is a placeholder; you'd put the actual commands here.
    # Example:
    # curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && \
    # chmod +x msfinstall && ./msfinstall
    sudo apt update && sudo apt install -y metasploit-framework
    if [[ $? -ne 0 ]]; then
        display_message "error" "$(_ install_msg_failed) Metasploit Framework. Review manual installation steps."
        return 1
    else
        display_message "success" "$(_ install_msg_end) Metasploit Framework."
        return 0
    fi
}

install_empire() {
    install_git_tool "Empire C2" "https://github.com/BC-SECURITY/Empire.git" "/opt/Empire" && \
    (cd /opt/Empire && sudo pip3 install -r requirements.txt) && \
    display_message "info" "$(_ empire_install_info)"
    return $?
}

install_sliver() {
    display_message "info" "$(_ download_msg) Sliver C2..."
    # Fetch the latest Linux version
    local version="1.5.2" # Example version, update as needed
    local server_url="https://github.com/BishopFox/sliver/releases/download/v${version}/sliver-server_linux"
    local client_url="https://github.com/BishopFox/sliver/releases/download/v${version}/sliver-client_linux"
    
    sudo wget -q "${server_url}" -O /usr/local/bin/sliver-server
    if [[ $? -ne 0 ]]; then
        display_message "error" "$(_ sliver_download_fail)"
        return 1
    fi
    sudo chmod +x /usr/local/bin/sliver-server
    
    sudo wget -q "${client_url}" -O /usr/local/bin/sliver-client
    if [[ $? -ne 0 ]]; then
        display_message "error" "$(_ sliver_client_download_fail)"
        return 1
    fi
    sudo chmod +x /usr/local/bin/sliver-client
    
    display_message "success" "$(_ install_msg_end) Sliver C2 (server & client)."
    return 0
}


install_ghost() {
    install_git_tool "Ghost Framework" "https://github.com/GhostFramework/GhostFramework" "/opt/ghost"
    if [[ $? -ne 0 ]]; then
        display_message "error" "$(_ ghost_clone_fail)"
        return 1
    fi
    # Additional installation steps for Ghost Framework
    if [ -d "/opt/ghost" ]; then
        cd /opt/ghost || { display_message "error" "$(_ dir_change_fail) /opt/ghost"; return 1; }
        pip3 install -r requirements.txt &> /dev/null # Or setup.py, depending on the tool
        if [[ $? -ne 0 ]]; then
            display_message "error" "$(_ ghost_install_fail)"
            return 1
        fi
        cd - > /dev/null # Go back to previous directory
    fi
    return 0
}

install_impacket() {
    install_git_tool "Impacket" "https://github.com/SecureAuthCorp/impacket.git" "/opt/impacket"
    if [[ $? -ne 0 ]]; then
        display_message "error" "$(_ impacket_clone_fail)"
        return 1
    fi
    if [ -d "/opt/impacket" ]; then
        cd /opt/impacket || { display_message "error" "$(_ dir_change_fail) /opt/impacket"; return 1; }
        pip3 install . &> /dev/null
        if [[ $? -ne 0 ]]; then
            display_message "error" "$(_ impacket_install_fail)"
            return 1
        fi
        cd - > /dev/null
    fi
    return 0
}

install_cme() {
    # CrackMapExec is usually installed via pipx for system-wide access
    display_message "info" "$(_ install_msg_start) CrackMapExec (CME)..."
    install_apt_tool "pipx" "pipx" # Ensure pipx is installed first
    if [[ $? -ne 0 ]]; then return 1; fi
    pipx ensurepath
    pipx install crackmapexec &> /dev/null
    if [[ $? -ne 0 ]]; then
        display_message "error" "$(_ cme_install_fail)"
        return 1
    else
        display_message "success" "$(_ install_msg_end) CrackMapExec (CME)."
        return 0
    fi
}

# --- دالة لتثبيت جميع الأدوات دفعة واحدة ---
install_all_tools() {
    display_message "info" "$(_ install_all_confirm)"
    read -r -p "[y/N]: " confirm_all_install
    if [[ "$confirm_all_install" =~ ^[Yy]$ ]]; then
        display_message "info" "$(_ install_all_starting)"
        # Add all your installation functions here
        install_metasploit
        install_empire
        install_sliver
        install_ghost
        install_impacket
        install_cme
        install_apt_tool "Bettercap" "bettercap"
        install_apt_tool "Ettercap" "ettercap-graphical"
        install_apt_tool "Wireshark" "wireshark"
        install_apt_tool "John the Ripper" "john"
        install_apt_tool "Hashcat" "hashcat"
        install_apt_tool "Hydra" "hydra"
        install_apt_tool "Medusa" "medusa"
        install_apt_tool "Aircrack-ng" "aircrack-ng"
        install_apt_tool "Wifite2" "wifite" # Check package name for wifite2
        install_apt_tool "Kismet" "kismet"
        install_apt_tool "Reaver" "reaver"
        install_apt_tool "PixieWPS" "pixiewps"
        install_apt_tool "Wifiphisher" "wifiphisher"
        install_apt_tool "SQLMap" "sqlmap"
        install_apt_tool "XSSer" "xsser"
        install_apt_tool "XSStrike" "xsstrike" # May need pip install
        install_apt_tool "Nikto" "nikto"
        install_apt_tool "Dirb" "dirb"
        install_apt_tool "Gobuster" "gobuster"
        install_apt_tool "WFuzz" "wfuzz"
        install_apt_tool "Nmap" "nmap"
        install_apt_tool "Netcat" "netcat-traditional" # or netcat-openbsd
        install_apt_tool "Tcpdump" "tcpdump"
        install_apt_tool "HTTrack" "httrack"
        install_apt_tool "Binwalk" "binwalk"
        install_apt_tool "ExifTool" "exiftool"
        install_apt_tool "Macchanger" "macchanger"
        install_apt_tool "Proxychains" "proxychains"
        
        display_message "success" "$(_ install_all_complete)"
        read -n 1 -s -r -p "$(_ press_any_key)"
    else
        display_message "info" "$(_ update_skipped)"
    fi
}


# ----------------------------------------------------
# FUNCTIONS FOR EACH TOOL LAUNCH (EXAMPLE, YOU NEED TO FILL THESE)
# ----------------------------------------------------

launch_metasploit() {
    display_message "info" "$(_ launch_msf_desc)"
    msfconsole
    read -n 1 -s -r -p "$(_ press_any_key)"
}

launch_empire() {
    display_message "info" "$(_ launch_empire_desc)"
    # This might require manual navigation and execution
    display_message "info" "Change directory to /opt/Empire and run 'sudo python3 ./empire'"
    read -n 1 -s -r -p "$(_ press_any_key)"
}

launch_sliver_server() {
    display_message "info" "$(_ launch_sliver_server_desc)"
    sudo sliver-server
    read -n 1 -s -r -p "$(_ press_any_key)"
}

launch_sliver_client() {
    display_message "info" "$(_ launch_sliver_client_desc)"
    sliver-client
    read -n 1 -s -r -p "$(_ press_any_key)"
}

launch_cme() {
    display_message "info" "$(_ launch_cme_desc)"
    read -r -p "${BLUE}Enter CME command arguments (e.g., smb 192.168.1.0/24): ${NC}" cme_args
    cme $cme_args
    read -n 1 -s -r -p "$(_ press_any_key)"
}

launch_wireshark() {
    display_message "info" "$(_ launch_wireshark_desc)"
    sudo wireshark & # Runs in background
    read -n 1 -s -r -p "$(_ press_any_key)"
}

launch_nmap() {
    display_message "info" "$(_ launch_nmap_desc)"
    read -r -p "${BLUE}Enter Nmap command arguments (e.g., -sV -sC 192.168.1.1): ${NC}" nmap_args
    nmap $nmap_args
    read -n 1 -s -r -p "$(_ press_any_key)"
}

launch_john() {
    display_message "info" "$(_ launch_john_desc)"
    read -r -p "${BLUE}Enter John the Ripper command arguments (e.g., --wordlist=passwords.txt hash.txt): ${NC}" john_args
    john $john_args
    read -n 1 -s -r -p "$(_ press_any_key)"
}

launch_hashcat() {
    display_message "info" "$(_ launch_hashcat_desc)"
    read -r -p "${BLUE}Enter Hashcat command arguments (e.g., -m 0 -a 0 hash.txt dict.txt): ${NC}" hashcat_args
    hashcat $hashcat_args
    read -n 1 -s -r -p "$(_ press_any_key)"
}

launch_hydra() {
    display_message "info" "$(_ launch_hydra_desc)"
    read -r -p "${BLUE}Enter Hydra command arguments (e.g., -L users.txt -P pass.txt 192.168.1.1 ssh): ${NC}" hydra_args
    hydra $hydra_args
    read -n 1 -s -r -p "$(_ press_any_key)"
}

launch_aircrackng() {
    display_message "info" "$(_ launch_aircrackng_desc)"
    read -r -p "${BLUE}Enter Aircrack-ng command arguments (e.g., -b [BSSID] capture.cap): ${NC}" aircrack_args
    aircrack-ng $aircrack_args
    read -n 1 -s -r -p "$(_ press_any_key)"
}

launch_sqlmap() {
    display_message "info" "$(_ launch_sqlmap_desc)"
    read -r -p "${BLUE}Enter SQLMap command arguments (e.g., -u http://example.com/id=1 --dbs): ${NC}" sqlmap_args
    sqlmap $sqlmap_args
    read -n 1 -s -r -p "$(_ press_any_key)"
}

launch_nipe() {
    display_message "info" "$(_ launch_nipe_desc)"
    read -r -p "${BLUE}Enter Nipe command (start/stop/restart/status): ${NC}" nipe_cmd
    sudo nipe $nipe_cmd
    read -n 1 -s -r -p "$(_ press_any_key)"
}

launch_macchanger() {
    display_message "info" "$(_ launch_macchanger_desc)"
    read -r -p "${BLUE}Enter interface (e.g., eth0, wlan0) and arguments (e.g., -r): ${NC}" mc_args
    sudo macchanger $mc_args
    read -n 1 -s -r -p "$(_ press_any_key)"
}

launch_proxychains() {
    display_message "info" "$(_ launch_proxychains_desc)"
    read -r -p "${BLUE}Enter command to run with proxychains (e.g., nmap -sT 192.168.1.1): ${NC}" pc_cmd
    proxychains $pc_cmd
    read -n 1 -s -r -p "$(_ press_any_key)"
}


# --- System Maintenance Functions ---

update_system_and_base_essentials() {
    display_message "info" "$(_ update_system_desc)"
    display_message "info" "$(_ check_updates_msg)"
    sudo apt update
    if [[ $? -ne 0 ]]; then
        display_message "error" "$(_ system_update_fail)"
        read -n 1 -s -r -p "$(_ press_any_key)"
        return 1
    fi

    display_message "info" "$(_ updates_found_prompt)"
    read -r -p "[y/N]: " confirm_update
    if [[ "$confirm_update" =~ ^[Yy]$ ]]; then
        display_message "info" "$(_ update_started)"
        sudo apt upgrade -y && sudo apt dist-upgrade -y && sudo apt autoremove -y
        if [[ $? -ne 0 ]]; then
            display_message "error" "$(_ system_update_fail)"
            read -n 1 -s -r -p "$(_ press_any_key)"
            return 1
        fi
        # Install common base tools if not present
        display_message "info" "$(_ install_msg_start) essential base tools (git, python3, pip3, curl, wget)..."
        sudo apt install -y git python3 python3-pip curl wget &> /dev/null
        if [[ $? -ne 0 ]]; then
            display_message "error" "$(_ base_tools_fail)"
            read -n 1 -s -r -p "$(_ press_any_key)"
            return 1
        fi
        display_message "success" "$(_ no_updates_needed)"
        read -n 1 -s -r -p "$(_ press_any_key)"
    else
        display_message "info" "$(_ update_skipped)"
        read -n 1 -s -r -p "$(_ press_any_key)"
    fi
    return 0
}

perform_cleanup() {
    display_message "info" "$(_ cleanup_start)"
    sudo apt clean && sudo apt autoclean && sudo apt autoremove -y
    display_message "success" "$(_ cleanup_complete)"
    read -n 1 -s -r -p "$(_ press_any_key)"
}

# --- Menus Structure ---
show_main_menu() {
  clear
  echo -e "${CYAN}==================================================${NC}"
  echo -e "${GREEN}       NOVA TEAM ELITE TOOLKIT - Main Menu      ${NC}"
  echo -e "${CYAN}==================================================${NC}"
  echo ""
  echo -e "${GREEN}  [1] $(_ install_tools_section)${NC}"
  echo -e "${GREEN}  [2] $(_ run_tools_section)${NC}"
  echo -e "${GREEN}  [3] $(_ system_maintenance_section)${NC}"
  echo -e "${GREEN}  [4] $(_ contact_section)${NC}"
  echo -e "${RED}  [0] $(_ exit_tool)${NC}"
  echo ""
  echo -n -e "${BLUE}$(_ enter_choice)${NC} "
}

show_install_menu() {
  clear
  echo -e "${CYAN}==================================================${NC}"
  echo -e "${GREEN}       NOVA TEAM ELITE TOOLKIT - Installation     ${NC}"
  echo -e "${CYAN}==================================================${NC}"
  echo ""
  echo -e "${GREEN}  [A] $(_ install_all_desc)${NC}" # New option for installing all tools
  echo -e "${GREEN}  [B] $(_ update_system_desc)${NC}" # Renamed and moved system update here

  echo -e "${YELLOW}\n  --- Categories ---${NC}"
  echo -e "${GREEN}  [1] $(_ cat_c2_rat_post)${NC}"
  echo -e "${GREEN}  [2] $(_ cat_mitm_sniffing)${NC}"
  echo -e "${GREEN}  [3] $(_ cat_windows_ad_exploit)${NC}"
  echo -e "${GREEN}  [4] $(_ cat_android_mobile)${NC}"
  echo -e "${GREEN}  [5] $(_ cat_password_attacks)${NC}"
  echo -e "${GREEN}  [6] $(_ cat_wifi_wireless)${NC}"
  echo -e "${GREEN}  [7] $(_ cat_web_exploitation)${NC}"
  echo -e "${GREEN}  [8] $(_ cat_privacy_anonymity)${NC}"
  echo -e "${GREEN}  [9] $(_ cat_useful_utilities)${NC}"
  echo ""
  echo -e "${RED}  [0] $(_ back_to_main_menu)${NC}"
  echo ""
  echo -n -e "${BLUE}$(_ enter_choice)${NC} "
}


show_run_menu() {
  clear
  echo -e "${CYAN}==================================================${NC}"
  echo -e "${GREEN}        NOVA TEAM ELITE TOOLKIT - Launch         ${NC}"
  echo -e "${CYAN}==================================================${NC}"
  echo ""
  echo -e "${YELLOW}\n  --- Categories ---${NC}"
  echo -e "${GREEN}  [1] $(_ cat_c2_rat_post)${NC}"
  echo -e "${GREEN}  [2] $(_ cat_mitm_sniffing)${NC}"
  echo -e "${GREEN}  [3] $(_ cat_windows_ad_exploit)${NC}"
  echo -e "${GREEN}  [4] $(_ cat_android_mobile)${NC}"
  echo -e "${GREEN}  [5] $(_ cat_password_attacks)${NC}"
  echo -e "${GREEN}  [6] $(_ cat_wifi_wireless)${NC}"
  echo -e "${GREEN}  [7] $(_ cat_web_exploitation)${NC}"
  echo -e "${GREEN}  [8] $(_ cat_privacy_anonymity)${NC}"
  echo -e "${GREEN}  [9] $(_ cat_useful_utilities)${NC}"
  echo ""
  echo -e "${RED}  [0] $(_ back_to_main_menu)${NC}"
  echo ""
  echo -n -e "${BLUE}$(_ enter_choice)${NC} "
}

show_system_maintenance_menu() {
  clear
  echo -e "${CYAN}==================================================${NC}"
  echo -e "${GREEN}     NOVA TEAM ELITE TOOLKIT - System Maintenance ${NC}"
  echo -e "${CYAN}==================================================${NC}"
  echo ""
  echo -e "${GREEN}  [1] $(_ update_system_desc)${NC}"
  echo -e "${GREEN}  [2] $(_ cleanup_start)${NC}" # Re-using cleanup_start as description
  echo ""
  echo -e "${RED}  [0] $(_ back_to_main_menu)${NC}"
  echo ""
  echo -n -e "${BLUE}$(_ enter_choice)${NC} "
}

show_contact_menu() {
    clear
    echo -e "${CYAN}==================================================${NC}"
    echo -e "${GREEN}          NOVA TEAM ELITE TOOLKIT - Contact       ${NC}"
    echo -e "${CYAN}==================================================${NC}"
    echo ""
    echo -e "${YELLOW}  For support, feedback, or collaboration, reach out to us!${NC}"
    echo ""
    echo -e "${GREEN}  🌐 Website: Coming Soon!${NC}"
    echo -e "${GREEN}  💬 Discord: $(_ contact_discord)${NC}"
    echo -e "${GREEN}  📧 Email: support@novateam.com (Example)${NC}"
    echo ""
    echo -e "${RED}  [0] $(_ back_to_main_menu)${NC}"
    echo ""
    echo -n -e "${BLUE}$(_ enter_choice)${NC} "
    read -r contact_choice
    case $contact_choice in
        0) return ;;
        *) display_message "invalid_option" "$(_ invalid_option)"; sleep 1; show_contact_menu ;;
    esac
}

# --- Tool Listing Functions (Install) ---
list_install_c2_rat_post() {
    clear
    echo -e "${CYAN}==================================================${NC}"
    echo -e "${GREEN}  INSTALL: $(_ cat_c2_rat_post) ${NC}"
    echo -e "${CYAN}==================================================${NC}"
    echo ""
    echo -e "${GREEN}  [1] $(_ install_msf_desc)${NC}"
    echo -e "${GREEN}  [2] $(_ install_empire_desc)${NC}"
    echo -e "${YELLOW}  [3] $(_ install_pupy_desc) (Manual)${NC}"
    echo -e "${GREEN}  [4] $(_ install_sliver_desc)${NC}"
    echo -e "${YELLOW}  [5] $(_ install_covenant_desc) (Manual/Docker)${NC}"
    echo -e "${YELLOW}  [6] $(_ install_quasarrat_desc) (Manual)${NC}"
    echo ""
    echo -e "${RED}  [0] $(_ back_to_prev_menu)${NC}"
    echo ""
    echo -n -e "${BLUE}$(_ enter_choice)${NC} "
}

list_install_mitm_sniffing() {
    clear
    echo -e "${CYAN}==================================================${NC}"
    echo -e "${GREEN}  INSTALL: $(_ cat_mitm_sniffing) ${NC}"
    echo -e "${CYAN}==================================================${NC}"
    echo ""
    echo -e "${GREEN}  [1] $(_ install_bettercap_desc)${NC}"
    echo -e "${GREEN}  [2] $(_ install_ettercap_desc)${NC}"
    echo -e "${YELLOW}  [3] $(_ install_evilginx2_desc) (Manual)${NC}"
    echo -e "${GREEN}  [4] $(_ install_wireshark_desc)${NC}"
    echo -e "${YELLOW}  [5] $(_ install_mitmf_desc) (Complex Manual)${NC}"
    echo -e "${YELLOW}  [6] $(_ install_fruitywifi_desc) (Complex Manual)${NC}"
    echo ""
    echo -e "${RED}  [0] $(_ back_to_prev_menu)${NC}"
    echo ""
    echo -n -e "${BLUE}$(_ enter_choice)${NC} "
}

list_install_windows_ad() {
    clear
    echo -e "${CYAN}==================================================${NC}"
    echo -e "${GREEN}  INSTALL: $(_ cat_windows_ad_exploit) ${NC}"
    echo -e "${CYAN}==================================================${NC}"
    echo ""
    echo -e "${GREEN}  [1] $(_ install_cme_desc)${NC}"
    echo -e "${GREEN}  [2] $(_ install_bloodhound_desc)${NC}" # Needs neo4j
    echo -e "${YELLOW}  [3] $(_ install_sharphound_desc) (Windows Binary)${NC}"
    echo -e "${YELLOW}  [4] $(_ install_mimikatz_desc) (Windows Binary)${NC}"
    echo -e "${GREEN}  [5] $(_ install_impacket_desc)${NC}"
    echo -e "${GREEN}  [6] $(_ install_responder_desc)${NC}"
    echo -e "${GREEN}  [7] $(_ install_kerbrute_desc)${NC}"
    echo -e "${GREEN}  [8] $(_ install_rpcclient_smbclient_desc)${NC}"
    echo ""
    echo -e "${RED}  [0] $(_ back_to_prev_menu)${NC}"
    echo ""
    echo -n -e "${BLUE}$(_ enter_choice)${NC} "
}

list_install_android_mobile() {
    clear
    echo -e "${CYAN}==================================================${NC}"
    echo -e "${GREEN}  INSTALL: $(_ cat_android_mobile) ${NC}"
    echo -e "${CYAN}==================================================${NC}"
    echo ""
    echo -e "${GREEN}  [1] $(_ install_ghost_desc)${NC}"
    echo -e "${YELLOW}  [2] $(_ install_evildroid_desc) (Manual)${NC}"
    echo -e "${YELLOW}  [3] $(_ install_ahmyth_desc) (Manual)${NC}"
    echo -e "${YELLOW}  [4] $(_ install_mobsf_desc) (Manual/Docker)${NC}"
    echo -e "${YELLOW}  [5] $(_ install_androrat_desc) (Manual)${NC}"
    echo ""
    echo -e "${RED}  [0] $(_ back_to_prev_menu)${NC}"
    echo ""
    echo -n -e "${BLUE}$(_ enter_choice)${NC} "
}

list_install_password_attacks() {
    clear
    echo -e "${CYAN}==================================================${NC}"
    echo -e "${GREEN}  INSTALL: $(_ cat_password_attacks) ${NC}"
    echo -e "${CYAN}==================================================${NC}"
    echo ""
    echo -e "${GREEN}  [1] $(_ install_john_desc)${NC}"
    echo -e "${GREEN}  [2] $(_ install_hashcat_desc)${NC}"
    echo -e "${GREEN}  [3] $(_ install_hydra_desc)${NC}"
    echo -e "${GREEN}  [4] $(_ install_medusa_desc)${NC}"
    echo -e "${GREEN}  [5] $(_ install_seclists_desc)${NC}"
    echo -e "${GREEN}  [6] $(_ install_crunch_desc)${NC}"
    echo ""
    echo -e "${RED}  [0] $(_ back_to_prev_menu)${NC}"
    echo ""
    echo -n -e "${BLUE}$(_ enter_choice)${NC} "
}

list_install_wifi_wireless() {
    clear
    echo -e "${CYAN}==================================================${NC}"
    echo -e "${GREEN}  INSTALL: $(_ cat_wifi_wireless) ${NC}"
    echo -e "${CYAN}==================================================${NC}"
    echo ""
    echo -e "${GREEN}  [1] $(_ install_aircrackng_desc)${NC}"
    echo -e "${GREEN}  [2] $(_ install_wifite2_desc)${NC}"
    echo -e "${GREEN}  [3] $(_ install_kismet_desc)${NC}"
    echo -e "${GREEN}  [4] $(_ install_reaver_desc)${NC}"
    echo -e "${GREEN}  [5] $(_ install_pixiewps_desc)${NC}"
    echo -e "${GREEN}  [6] $(_ install_wifiphisher_desc)${NC}"
    echo ""
    echo -e "${RED}  [0] $(_ back_to_prev_menu)${NC}"
    echo ""
    echo -n -e "${BLUE}$(_ enter_choice)${NC} "
}

list_install_web_exploitation() {
    clear
    echo -e "${CYAN}==================================================${NC}"
    echo -e "${GREEN}  INSTALL: $(_ cat_web_exploitation) ${NC}"
    echo -e "${CYAN}==================================================${NC}"
    echo ""
    echo -e "${GREEN}  [1] $(_ install_sqlmap_desc)${NC}"
    echo -e "${GREEN}  [2] $(_ install_xsser_desc)${NC}"
    echo -e "${GREEN}  [3] $(_ install_xsstrike_desc)${NC}"
    echo -e "${GREEN}  [4] $(_ install_nikto_desc)${NC}"
    echo -e "${GREEN}  [5] $(_ install_dirb_dirbuster_desc)${NC}"
    echo -e "${GREEN}  [6] $(_ install_gobuster_desc)${NC}"
    echo -e "${GREEN}  [7] $(_ install_wfuzz_desc)${NC}"
    echo -e "${YELLOW}  [8] $(_ install_burpsuite_desc) (Manual)${NC}"
    echo ""
    echo -e "${RED}  [0] $(_ back_to_prev_menu)${NC}"
    echo ""
    echo -n -e "${BLUE}$(_ enter_choice)${NC} "
}

list_install_privacy_anonymity() {
    clear
    echo -e "${CYAN}==================================================${NC}"
    echo -e "${GREEN}  INSTALL: $(_ cat_privacy_anonymity) ${NC}"
    echo -e "${CYAN}==================================================${NC}"
    echo ""
    echo -e "${GREEN}  [1] $(_ install_nipe_desc)${NC}"
    echo -e "${GREEN}  [2] $(_ install_tor_desc)${NC}"
    echo -e "${GREEN}  [3] $(_ install_macchanger_desc)${NC}"
    echo -e "${GREEN}  [4] $(_ install_proxychains_desc)${NC}"
    echo -e "${YELLOW}  [5] $(_ install_chameleon_desc) (Manual)${NC}"
    echo ""
    echo -e "${RED}  [0] $(_ back_to_prev_menu)${NC}"
    echo ""
    echo -n -e "${BLUE}$(_ enter_choice)${NC} "
}

list_install_useful_utilities() {
    clear
    echo -e "${CYAN}==================================================${NC}"
    echo -e "${GREEN}  INSTALL: $(_ cat_useful_utilities) ${NC}"
    echo -e "${CYAN}==================================================${NC}"
    echo ""
    echo -e "${GREEN}  [1] $(_ install_netcat_desc)${NC}"
    echo -e "${GREEN}  [2] $(_ install_nmap_desc)${NC}"
    echo -e "${GREEN}  [3] $(_ install_tcpdump_desc)${NC}"
    echo -e "${GREEN}  [4] $(_ install_httrack_desc)${NC}"
    echo -e "${GREEN}  [5] $(_ install_binwalk_desc)${NC}"
    echo -e "${GREEN}  [6] $(_ install_exiftool_desc)${NC}"
    echo -e "${YELLOW}  [7] $(_ install_ghidra_desc) (Manual)${NC}"
    echo ""
    echo -e "${RED}  [0] $(_ back_to_prev_menu)${NC}"
    echo ""
    echo -n -e "${BLUE}$(_ enter_choice)${NC} "
}

# --- Tool Listing Functions (Launch) ---
list_launch_c2_rat_post() {
    clear
    echo -e "${CYAN}==================================================${NC}"
    echo -e "${GREEN}  LAUNCH: $(_ cat_c2_rat_post) ${NC}"
    echo -e "${CYAN}==================================================${NC}"
    echo ""
    echo -e "${GREEN}  [1] $(_ launch_msf_desc)${NC}"
    echo -e "${YELLOW}  [2] $(_ launch_empire_desc)${NC}"
    echo -e "${YELLOW}  [3] $(_ launch_pupy_desc)${NC}"
    echo -e "${GREEN}  [4] $(_ launch_sliver_server_desc)${NC}"
    echo -e "${GREEN}  [5] $(_ launch_sliver_client_desc)${NC}"
    echo -e "${YELLOW}  [6] $(_ launch_covenant_desc)${NC}"
    echo -e "${YELLOW}  [7] $(_ launch_quasarrat_desc)${NC}"
    echo ""
    echo -e "${RED}  [0] $(_ back_to_prev_menu)${NC}"
    echo ""
    echo -n -e "${BLUE}$(_ enter_choice)${NC} "
}

list_launch_mitm_sniffing() {
    clear
    echo -e "${CYAN}==================================================${NC}"
    echo -e "${GREEN}  LAUNCH: $(_ cat_mitm_sniffing) ${NC}"
    echo -e "${CYAN}==================================================${NC}"
    echo ""
    echo -e "${GREEN}  [1] $(_ launch_bettercap_desc)${NC}"
    echo -e "${GREEN}  [2] $(_ launch_ettercap_desc)${NC}"
    echo -e "${YELLOW}  [3] $(_ launch_evilginx2_desc)${NC}"
    echo -e "${GREEN}  [4] $(_ launch_wireshark_desc)${NC}"
    echo -e "${YELLOW}  [5] $(_ launch_mitmf_desc)${NC}"
    echo -e "${YELLOW}  [6] $(_ launch_fruitywifi_desc)${NC}"
    echo ""
    echo -e "${RED}  [0] $(_ back_to_prev_menu)${NC}"
    echo ""
    echo -n -e "${BLUE}$(_ enter_choice)${NC} "
}

list_launch_windows_ad() {
    clear
    echo -e "${CYAN}==================================================${NC}"
    echo -e "${GREEN}  LAUNCH: $(_ cat_windows_ad_exploit) ${NC}"
    echo -e "${CYAN}==================================================${NC}"
    echo ""
    echo -e "${GREEN}  [1] $(_ launch_cme_desc)${NC}"
    echo -e "${YELLOW}  [2] $(_ launch_bloodhound_desc)${NC}"
    echo -e "${YELLOW}  [3] $(_ launch_sharphound_desc)${NC}"
    echo -e "${YELLOW}  [4] $(_ launch_mimikatz_desc)${NC}"
    echo -e "${GREEN}  [5] $(_ launch_impacket_desc)${NC}"
    echo -e "${GREEN}  [6] $(_ launch_responder_desc)${NC}"
    echo -e "${GREEN}  [7] $(_ launch_kerbrute_desc)${NC}"
    echo -e "${GREEN}  [8] $(_ launch_rpcclient_desc)${NC}"
    echo -e "${GREEN}  [9] $(_ launch_smbclient_desc)${NC}"
    echo ""
    echo -e "${RED}  [0] $(_ back_to_prev_menu)${NC}"
    echo ""
    echo -n -e "${BLUE}$(_ enter_choice)${NC} "
}

list_launch_android_mobile() {
    clear
    echo -e "${CYAN}==================================================${NC}"
    echo -e "${GREEN}  LAUNCH: $(_ cat_android_mobile) ${NC}"
    echo -e "${CYAN}==================================================${NC}"
    echo ""
    echo -e "${GREEN}  [1] $(_ launch_ghost_desc)${NC}"
    echo -e "${YELLOW}  [2] $(_ launch_evildroid_desc)${NC}"
    echo -e "${YELLOW}  [3] $(_ launch_ahmyth_desc)${NC}"
    echo -e "${YELLOW}  [4] $(_ launch_mobsf_desc)${NC}"
    echo -e "${YELLOW}  [5] $(_ launch_androrat_desc)${NC}"
    echo ""
    echo -e "${RED}  [0] $(_ back_to_prev_menu)${NC}"
    echo ""
    echo -n -e "${BLUE}$(_ enter_choice)${NC} "
}

list_launch_password_attacks() {
    clear
    echo -e "${CYAN}==================================================${NC}"
    echo -e "${GREEN}  LAUNCH: $(_ cat_password_attacks) ${NC}"
    echo -e "${CYAN}==================================================${NC}"
    echo ""
    echo -e "${GREEN}  [1] $(_ launch_john_desc)${NC}"
    echo -e "${GREEN}  [2] $(_ launch_hashcat_desc)${NC}"
    echo -e "${GREEN}  [3] $(_ launch_hydra_desc)${NC}"
    echo -e "${GREEN}  [4] $(_ launch_medusa_desc)${NC}"
    echo -e "${YELLOW}  [5] $(_ launch_seclists_desc) (Info)${NC}"
    echo -e "${GREEN}  [6] $(_ launch_crunch_desc)${NC}"
    echo ""
    echo -e "${RED}  [0] $(_ back_to_prev_menu)${NC}"
    echo ""
    echo -n -e "${BLUE}$(_ enter_choice)${NC} "
}

list_launch_wifi_wireless() {
    clear
    echo -e "${CYAN}==================================================${NC}"
    echo -e "${GREEN}  LAUNCH: $(_ cat_wifi_wireless) ${NC}"
    echo -e "${CYAN}==================================================${NC}"
    echo ""
    echo -e "${GREEN}  [1] $(_ launch_aircrackng_desc)${NC}"
    echo -e "${GREEN}  [2] $(_ launch_wifite2_desc)${NC}"
    echo -e "${GREEN}  [3] $(_ launch_kismet_desc)${NC}"
    echo -e "${GREEN}  [4] $(_ launch_reaver_desc)${NC}"
    echo -e "${GREEN}  [5] $(_ launch_pixiewps_desc)${NC}"
    echo -e "${GREEN}  [6] $(_ launch_wifiphisher_desc)${NC}"
    echo ""
    echo -e "${RED}  [0] $(_ back_to_prev_menu)${NC}"
    echo ""
    echo -n -e "${BLUE}$(_ enter_choice)${NC} "
}

list_launch_web_exploitation() {
    clear
    echo -e "${CYAN}==================================================${NC}"
    echo -e "${GREEN}  LAUNCH: $(_ cat_web_exploitation) ${NC}"
    echo -e "${CYAN}==================================================${NC}"
    echo ""
    echo -e "${GREEN}  [1] $(_ launch_sqlmap_desc)${NC}"
    echo -e "${GREEN}  [2] $(_ launch_xsser_desc)${NC}"
    echo -e "${GREEN}  [3] $(_ launch_xsstrike_desc)${NC}"
    echo -e "${GREEN}  [4] $(_ launch_nikto_desc)${NC}"
    echo -e "${GREEN}  [5] $(_ launch_dirb_desc)${NC}"
    echo -e "${YELLOW}  [6] $(_ launch_dirbuster_desc)${NC}"
    echo -e "${GREEN}  [7] $(_ launch_gobuster_desc)${NC}"
    echo -e "${GREEN}  [8] $(_ launch_wfuzz_desc)${NC}"
    echo -e "${YELLOW}  [9] $(_ launch_burpsuite_desc)${NC}"
    echo ""
    echo -e "${RED}  [0] $(_ back_to_prev_menu)${NC}"
    echo ""
    echo -n -e "${BLUE}$(_ enter_choice)${NC} "
}

list_launch_privacy_anonymity() {
    clear
    echo -e "${CYAN}==================================================${NC}"
    echo -e "${GREEN}  LAUNCH: $(_ cat_privacy_anonymity) ${NC}"
    echo -e "${CYAN}==================================================${NC}"
    echo ""
    echo -e "${GREEN}  [1] $(_ launch_nipe_desc)${NC}"
    echo -e "${GREEN}  [2] $(_ launch_tor_desc)${NC}"
    echo -e "${GREEN}  [3] $(_ launch_macchanger_desc)${NC}"
    echo -e "${GREEN}  [4] $(_ launch_proxychains_desc)${NC}"
    echo -e "${YELLOW}  [5] $(_ launch_chameleon_desc)${NC}"
    echo ""
    echo -e "${RED}  [0] $(_ back_to_prev_menu)${NC}"
    echo ""
    echo -n -e "${BLUE}$(_ enter_choice)${NC} "
}

list_launch_useful_utilities() {
    clear
    echo -e "${CYAN}==================================================${NC}"
    echo -e "${GREEN}  LAUNCH: $(_ cat_useful_utilities) ${NC}"
    echo -e "${CYAN}==================================================${NC}"
    echo ""
    echo -e "${GREEN}  [1] $(_ launch_netcat_desc)${NC}"
    echo -e "${GREEN}  [2] $(_ launch_nmap_desc)${NC}"
    echo -e "${GREEN}  [3] $(_ launch_tcpdump_desc)${NC}"
    echo -e "${GREEN}  [4] $(_ launch_httrack_desc)${NC}"
    echo -e "${GREEN}  [5] $(_ launch_binwalk_desc)${NC}"
    echo -e "${GREEN}  [6] $(_ launch_exiftool_desc)${NC}"
    echo -e "${YELLOW}  [7] $(_ launch_ghidra_desc)${NC}"
    echo ""
    echo -e "${RED}  [0] $(_ back_to_prev_menu)${NC}"
    echo ""
    echo -n -e "${BLUE}$(_ enter_choice)${NC} "
}


# --- Main Loop ---
main_menu_loop() {
  while true; do
    show_main_menu
    read -r main_choice
    case $main_choice in
      1) install_menu_loop ;;
      2) run_menu_loop ;;
      3) system_maintenance_menu_loop ;;
      4) show_contact_menu ;;
      0) display_message "success" "$(_ exit_success)"; exit 0 ;;
      *) display_message "error" "$(_ invalid_option)"; sleep 1 ;;
    esac
  done
}

install_menu_loop() {
  while true; do
    show_install_menu
    read -r install_choice
    case $install_choice in
      A|a) install_all_tools ;;
      B|b) update_system_and_base_essentials ;;
      1)
        while true; do
          list_install_c2_rat_post
          read -r tool_choice
          case $tool_choice in
            1) install_metasploit ;;
            2) install_empire ;;
            3) display_message "info" "$(_ manual_install_info) https://github.com/n1nj4sec/pupy"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            4) install_sliver ;;
            5) display_message "info" "$(_ manual_install_info) https://github.com/RastaMouse/Covenant"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            6) display_message "info" "$(_ manual_install_info) https://github.com/quasar/QuasarRAT"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            0) break ;;
            *) display_message "error" "$(_ invalid_option)"; sleep 1 ;;
          esac
        done
        ;;
      2)
        while true; do
          list_install_mitm_sniffing
          read -r tool_choice
          case $tool_choice in
            1) install_apt_tool "Bettercap" "bettercap" ;;
            2) install_apt_tool "Ettercap" "ettercap-graphical" ;;
            3) display_message "info" "$(_ manual_install_info) https://github.com/kgretzky/evilginx2"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            4) install_apt_tool "Wireshark" "wireshark" ;;
            5) display_message "info" "$(_ manual_install_info) https://github.com/byt3bl33d3r/MITMf"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            6) display_message "info" "$(_ manual_install_info) https://github.com/xtr4nge/FruityWiFi"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            0) break ;;
            *) display_message "error" "$(_ invalid_option)"; sleep 1 ;;
          esac
        done
        ;;
      3)
        while true; do
          list_install_windows_ad
          read -r tool_choice
          case $tool_choice in
            1) install_cme ;;
            2) install_apt_tool "BloodHound" "bloodhound" ;; # BloodHound-Python client
            3) display_message "info" "$(_ manual_install_info) https://github.com/BloodHoundAD/SharpHound/releases"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            4) display_message "info" "$(_ manual_install_info) https://github.com/gentilkiwi/mimikatz/releases"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            5) install_impacket ;;
            6) install_git_tool "Responder" "https://github.com/lgandx/Responder.git" "/opt/Responder" ;;
            7) install_git_tool "Kerbrute" "https://github.com/ropnop/kerbrute.git" "/opt/kerbrute" && (cd /opt/kerbrute && go build ./) ;; # Requires GoLang
            8) install_apt_tool "rpcclient/smbclient" "smbclient" ;;
            0) break ;;
            *) display_message "error" "$(_ invalid_option)"; sleep 1 ;;
          esac
        done
        ;;
      4)
        while true; do
          list_install_android_mobile
          read -r tool_choice
          case $tool_choice in
            1) install_ghost ;;
            2) display_message "info" "$(_ manual_install_info) https://github.com/sufiankhair/Evil-Droid"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            3) display_message "info" "$(_ manual_install_info) https://github.com/AhMyth/AhMyth-Android-RAT"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            4) display_message "info" "$(_ manual_install_info) https://github.com/MobSF/Mobile-Security-Framework-MobSF"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            5) display_message "info" "$(_ manual_install_info) https://github.com/wszf/androrat"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            0) break ;;
            *) display_message "error" "$(_ invalid_option)"; sleep 1 ;;
          esac
        done
        ;;
      5)
        while true; do
          list_install_password_attacks
          read -r tool_choice
          case $tool_choice in
            1) install_apt_tool "John the Ripper" "john" ;;
            2) install_apt_tool "Hashcat" "hashcat" ;;
            3) install_apt_tool "Hydra" "hydra" ;;
            4) install_apt_tool "Medusa" "medusa" ;;
            5) install_git_tool "SecLists" "https://github.com/danielmiessler/SecLists.git" "/opt/SecLists" && display_message "success" "$(_ install_msg_end) SecLists to /opt/SecLists. You may also find a copy in /usr/share/seclists."; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            6) install_apt_tool "Crunch" "crunch" ;;
            0) break ;;
            *) display_message "error" "$(_ invalid_option)"; sleep 1 ;;
          esac
        done
        ;;
      6)
        while true; do
          list_install_wifi_wireless
          read -r tool_choice
          case $tool_choice in
            1) install_apt_tool "Aircrack-ng" "aircrack-ng" ;;
            2) install_apt_tool "Wifite2" "wifite" ;; # Check package name if wifite2 isn't directly available
            3) install_apt_tool "Kismet" "kismet" ;;
            4) install_apt_tool "Reaver" "reaver" ;;
            5) install_apt_tool "PixieWPS" "pixiewps" ;;
            6) install_apt_tool "Wifiphisher" "wifiphisher" ;;
            0) break ;;
            *) display_message "error" "$(_ invalid_option)"; sleep 1 ;;
          esac
        done
        ;;
      7)
        while true; do
          list_install_web_exploitation
          read -r tool_choice
          case $tool_choice in
            1) install_apt_tool "SQLMap" "sqlmap" ;;
            2) install_apt_tool "XSSer" "xsser" ;;
            3) install_git_tool "XSStrike" "https://github.com/s0md3v/XSStrike.git" "/opt/XSStrike" && (cd /opt/XSStrike && pip3 install -r requirements.txt) ;;
            4) install_apt_tool "Nikto" "nikto" ;;
            5) install_apt_tool "Dirb / Dirbuster" "dirb dirbuster" ;;
            6) install_apt_tool "Gobuster" "gobuster" ;;
            7) install_apt_tool "WFuzz" "wfuzz" ;;
            8) display_message "info" "$(_ manual_install_info) https://portswigger.net/burp/communitydownload"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            0) break ;;
            *) display_message "error" "$(_ invalid_option)"; sleep 1 ;;
          esac
        done
        ;;
      8)
        while true; do
          list_install_privacy_anonymity
          read -r tool_choice
          case $tool_choice in
            1) install_git_tool "Nipe" "https://github.com/htrgouvea/nipe.git" "/opt/nipe" && (cd /opt/nipe && sudo cpan install Try::Tiny Config::Simple JSON) && (cd /opt/nipe && sudo perl nipe.pl install) ;;
            2) install_apt_tool "Tor" "tor" ;;
            3) install_apt_tool "Macchanger" "macchanger" ;;
            4) install_apt_tool "Proxychains" "proxychains" ;;
            5) display_message "info" "$(_ manual_install_info) https://github.com/pwn-labs/Chameleon"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            0) break ;;
            *) display_message "error" "$(_ invalid_option)"; sleep 1 ;;
          esac
        done
        ;;
      9)
        while true; do
          list_install_useful_utilities
          read -r tool_choice
          case $tool_choice in
            1) install_apt_tool "Netcat" "netcat-traditional" ;;
            2) install_apt_tool "Nmap" "nmap" ;;
            3) install_apt_tool "tcpdump" "tcpdump" ;;
            4) install_apt_tool "HTTrack" "httrack" ;;
            5) install_apt_tool "Binwalk" "binwalk" ;;
            6) install_apt_tool "ExifTool" "exiftool" ;;
            7) display_message "info" "$(_ manual_install_info) https://github.com/NationalSecurityAgency/ghidra/releases"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            0) break ;;
            *) display_message "error" "$(_ invalid_option)"; sleep 1 ;;
          esac
        done
        ;;
      0) break ;;
      *) display_message "error" "$(_ invalid_option)"; sleep 1 ;;
    esac
  done
}

run_menu_loop() {
  while true; do
    show_run_menu
    read -r run_choice
    case $run_choice in
      1)
        while true; do
          list_launch_c2_rat_post
          read -r tool_choice
          case $tool_choice in
            1) launch_metasploit ;;
            2) launch_empire ;;
            3) display_message "info" "$(_ launch_pupy_desc)"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            4) launch_sliver_server ;;
            5) launch_sliver_client ;;
            6) display_message "info" "$(_ launch_covenant_desc)"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            7) display_message "info" "$(_ launch_quasarrat_desc)"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            0) break ;;
            *) display_message "error" "$(_ invalid_option)"; sleep 1 ;;
          esac
        done
        ;;
      2)
        while true; do
          list_launch_mitm_sniffing
          read -r tool_choice
          case $tool_choice in
            1) display_message "info" "$(_ launch_bettercap_desc)"; read -r -p "${BLUE}Enter interface (e.g., wlan0): ${NC}" iface; sudo bettercap -iface $iface; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            2) display_message "info" "$(_ launch_ettercap_desc)"; sudo ettercap -G; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            3) display_message "info" "$(_ launch_evilginx2_desc)"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            4) launch_wireshark ;;
            5) display_message "info" "$(_ launch_mitmf_desc)"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            6) display_message "info" "$(_ launch_fruitywifi_desc)"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            0) break ;;
            *) display_message "error" "$(_ invalid_option)"; sleep 1 ;;
          esac
        done
        ;;
      3)
        while true; do
          list_launch_windows_ad
          read -r tool_choice
          case $tool_choice in
            1) launch_cme ;;
            2) display_message "info" "$(_ launch_bloodhound_desc)"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            3) display_message "info" "$(_ launch_sharphound_desc)"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            4) display_message "info" "$(_ launch_mimikatz_desc)"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            5) display_message "info" "$(_ launch_impacket_desc)"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            6) display_message "info" "$(_ launch_responder_desc)"; read -r -p "${BLUE}Enter interface (e.g., eth0) and arguments (e.g., -rv): ${NC}" responder_args; sudo responder -i $responder_args; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            7) display_message "info" "$(_ launch_kerbrute_desc)"; read -r -p "${BLUE}Enter Kerbrute arguments (e.g., userenum --domain example.com users.txt): ${NC}" kerbrute_args; kerbrute $kerbrute_args; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            8) display_message "info" "$(_ launch_rpcclient_desc)"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            9) display_message "info" "$(_ launch_smbclient_desc)"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            0) break ;;
            *) display_message "error" "$(_ invalid_option)"; sleep 1 ;;
          esac
        done
        ;;
      4)
        while true; do
          list_launch_android_mobile
          read -r tool_choice
          case $tool_choice in
            1) display_message "info" "$(_ launch_ghost_desc)"; /opt/ghost/ghost; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            2) display_message "info" "$(_ launch_evildroid_desc)"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            3) display_message "info" "$(_ launch_ahmyth_desc)"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            4) display_message "info" "$(_ launch_mobsf_desc)"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            5) display_message "info" "$(_ launch_androrat_desc)"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            0) break ;;
            *) display_message "error" "$(_ invalid_option)"; sleep 1 ;;
          esac
        done
        ;;
      5)
        while true; do
          list_launch_password_attacks
          read -r tool_choice
          case $tool_choice in
            1) launch_john ;;
            2) launch_hashcat ;;
            3) launch_hydra ;;
            4) launch_medusa ;;
            5) display_message "info" "$(_ launch_seclists_desc)"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            6) display_message "info" "$(_ launch_crunch_desc)"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            0) break ;;
            *) display_message "error" "$(_ invalid_option)"; sleep 1 ;;
          esac
        done
        ;;
      6)
        while true; do
          list_launch_wifi_wireless
          read -r tool_choice
          case $tool_choice in
            1) launch_aircrackng ;;
            2) display_message "info" "$(_ launch_wifite2_desc)"; wifite; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            3) display_message "info" "$(_ launch_kismet_desc)"; sudo kismet; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            4) display_message "info" "$(_ launch_reaver_desc)"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            5) display_message "info" "$(_ launch_pixiewps_desc)"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            6) display_message "info" "$(_ launch_wifiphisher_desc)"; sudo wifiphisher; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            0) break ;;
            *) display_message "error" "$(_ invalid_option)"; sleep 1 ;;
          esac
        done
        ;;
      7)
        while true; do
          list_launch_web_exploitation
          read -r tool_choice
          case $tool_choice in
            1) launch_sqlmap ;;
            2) display_message "info" "$(_ launch_xsser_desc)"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            3) display_message "info" "$(_ launch_xsstrike_desc)"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            4) display_message "info" "$(_ launch_nikto_desc)"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            5) display_message "info" "$(_ launch_dirb_desc)"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            6) display_message "info" "$(_ launch_dirbuster_desc)"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            7) display_message "info" "$(_ launch_gobuster_desc)"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            8) display_message "info" "$(_ launch_wfuzz_desc)"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            9) display_message "info" "$(_ launch_burpsuite_desc)"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            0) break ;;
            *) display_message "error" "$(_ invalid_option)"; sleep 1 ;;
          esac
        done
        ;;
      8)
        while true; do
          list_launch_privacy_anonymity
          read -r tool_choice
          case $tool_choice in
            1) launch_nipe ;;
            2) display_message "info" "$(_ launch_tor_desc)"; sudo service tor start; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            3) launch_macchanger ;;
            4) launch_proxychains ;;
            5) display_message "info" "$(_ launch_chameleon_desc)"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            0) break ;;
            *) display_message "error" "$(_ invalid_option)"; sleep 1 ;;
          esac
        done
        ;;
      9)
        while true; do
          list_launch_useful_utilities
          read -r tool_choice
          case $tool_choice in
            1) display_message "info" "$(_ launch_netcat_desc)"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            2) launch_nmap ;;
            3) display_message "info" "$(_ launch_tcpdump_desc)"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            4) display_message "info" "$(_ launch_httrack_desc)"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            5) display_message "info" "$(_ launch_binwalk_desc)"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            6) display_message "info" "$(_ launch_exiftool_desc)"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            7) display_message "info" "$(_ launch_ghidra_desc)"; read -n 1 -s -r -p "$(_ press_any_key)" ;;
            0) break ;;
            *) display_message "error" "$(_ invalid_option)"; sleep 1 ;;
          esac
        done
        ;;
      0) break ;;
      *) display_message "error" "$(_ invalid_option)"; sleep 1 ;;
    esac
  done
}

system_maintenance_menu_loop() {
  while true; do
    show_system_maintenance_menu
    read -r sys_maint_choice
    case $sys_maint_choice in
      1) update_system_and_base_essentials ;;
      2) perform_cleanup ;;
      0) break ;;
      *) display_message "error" "$(_ invalid_option)"; sleep 1 ;;
    esac
  done
}


# --- Script Execution Flow ---
choose_language # Let user choose language first
show_ethical_warning # Show warning after language selection
main_menu_loop # Start the main menu
