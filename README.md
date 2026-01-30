\# Enterprise Penetration Testing \& Defense Project



\[!\[MITRE ATT\&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Framework-red)](https://attack.mitre.org/)

\[!\[Suricata](https://img.shields.io/badge/Suricata-IDS%2FIPS-orange)](https://suricata.io/)

\[!\[pfSense](https://img.shields.io/badge/pfSense-Firewall-blue)](https://www.pfsense.org/)



\## Project Overview



\*\*Final Project Grade: 97%\*\*



A comprehensive red team/blue team cybersecurity capstone project demonstrating full-scope penetration testing against a simulated enterprise network, followed by implementing defensive countermeasures. This project was completed as the final assessment for the \*\*Cybersecurity Professional Training Program\*\*



\### Project Requirements



This capstone required students to:

\- Design and deploy a complete enterprise network infrastructure (DMZ, internal LAN, firewall)

\- \*\*Disable Windows Firewall\*\* to implement custom security solutions (pfSense, Suricata IDS/IPS)

\- Execute a realistic attack scenario using OSINT, social engineering, and exploitation frameworks

\- Map all techniques to the MITRE ATT\&CK framework

\- Implement comprehensive defensive measures across multiple layers

\- Document the entire engagement professionally



\## 🎥 Video Presentation



\[!\[Watch the Demo](https://img.youtube.com/vi/tj2HYQXQXvM/maxresdefault.jpg)](https://youtu.be/tj2HYQXQXvM)



\*Click the image above to watch the full project demonstration on YouTube\*



\### Attack Scenario



Two competing construction companies are bidding on a lucrative government contract. The target organization (Signature Homes) faces a sophisticated cyber attack from a competitor (Carefree Homes) attempting to exfiltrate their encrypted bid documents.



\### Our Implementation



We chose to demonstrate:



\*\*Offensive Capabilities:\*\*

\- \*\*OSINT \& Reconnaissance:\*\* Social media scraping, website enumeration (gobuster, WPScan)

\- \*\*Social Engineering:\*\* Facebook profiles, spear-phishing emails, credential harvesting

\- \*\*Custom Payloads:\*\* Malicious HTA files, msfvenom reverse shells, service-based persistence

\- \*\*Privilege Escalation:\*\* Exploiting excessive admin rights, domain compromise

\- \*\*Lateral Movement:\*\* SMB file transfers, remote service execution across domain

\- \*\*Data Exfiltration:\*\* Encrypted file extraction and multi-stage decryption



\*\*Defensive Implementations:\*\*

\- \*\*Network Security:\*\* pfSense firewall with custom rule sets

\- \*\*Intrusion Detection/Prevention:\*\* 11 custom Suricata signatures mapped to attack techniques

\- \*\*Application Hardening:\*\* WordPress security plugins, rate limiting, access controls

\- \*\*Deception:\*\* Encrypted decoy files to waste attacker time

\- \*\*User Awareness:\*\* Security training program for employees



\*\*Objective:\*\* Execute a full attack chain, then implement comprehensive defensive measures to prevent such attacks.



\## 🎯 Skills Demonstrated



\### Offensive Security (Red Team)

\- \*\*Reconnaissance:\*\* OSINT via social media, website enumeration (gobuster, WPScan)

\- \*\*Initial Access:\*\* Spear phishing, credential harvesting, password cracking (Burp Suite, CUPP)

\- \*\*Execution:\*\* Malicious payload delivery (Metasploit, msfvenom)

\- \*\*Persistence:\*\* Windows service creation, registry manipulation

\- \*\*Privilege Escalation:\*\* Domain administrator compromise

\- \*\*Lateral Movement:\*\* SMB file transfer, remote service creation

\- \*\*Defense Evasion:\*\* Process migration, log clearing

\- \*\*Exfiltration:\*\* Encrypted file extraction and decryption (Base64, John the Ripper)



\### Defensive Security (Blue Team)

\- \*\*Network Security:\*\* pfSense firewall rule configuration

\- \*\*Intrusion Detection/Prevention:\*\* Custom Suricata IDS/IPS rules (11 signatures)

\- \*\*Web Application Security:\*\* WordPress hardening (login attempt limiting, page hiding)

\- \*\*Security Awareness:\*\* Employee training program development

\- \*\*Data Protection:\*\* File encryption, decoy files, access controls



\## 🏗️ Network Architecture



!\[Network Diagram](Network\_structure.jpg)



\*\*Network Segments:\*\*

| Segment | Subnet | Purpose |

|---------|--------|---------|

| WAN | 192.168.139.255 / 192.168.1.15 | Internet connection |

| DMZ | 192.168.8.1/24 | Public-facing web server |

| LAN | 192.168.7.1/24 | Internal corporate network |



\*\*Target Hosts:\*\*

| Host | IP Address | Role |

|------|------------|------|

| Website | 192.168.8.10 | WordPress company site |

| SH\_CEO | 192.168.7.15/.19 | CEO workstation (Adam) - Initial compromise |

| SH\_DC | 192.168.7.14 | Domain Controller |

| SH\_Commerce | 192.168.7.11 | Commerce workstation (Daniel) - Target data |

| SH\_Assistant | 192.168.7.13 | Assistant workstation |







\## 🔴 Attack Chain Summary



| Phase | MITRE Tactic | Technique | Tool/Method |

|-------|--------------|-----------|-------------|

| 1 | Reconnaissance | T1593 - Search Open Websites | Facebook, Company Website |

| 2 | Reconnaissance | T1595 - Active Scanning | gobuster, WPScan |

| 3 | Resource Development | T1586 - Compromise Accounts | Burp Suite + CUPP wordlist |

| 4 | Initial Access | T1566 - Phishing | Spoofed email + malicious HTA |

| 5 | Execution | T1059 - Command \& Scripting | msfvenom reverse shell |

| 6 | Persistence | T1543 - Create System Service | Windows service creation |

| 7 | Privilege Escalation | T1078 - Valid Accounts | Domain admin exploitation |

| 8 | Lateral Movement | T1570 - Lateral Tool Transfer | SMB + remote service exec |

| 9 | Collection | T1005 - Data from Local System | Target file discovery |

| 10 | Exfiltration | T1041 - Exfiltration Over C2 | Meterpreter download |

| 11 | Impact | T1565 - Data Manipulation | Decoy file encounter |



\## 🗺️ MITRE ATT\&CK Heatmap



The following visualizations show which MITRE ATT\&CK techniques were employed during this engagement (highlighted cells indicate techniques used):



<details>

<summary><b>View MITRE ATT\&CK Technique Coverage</b> (click to expand)</summary>



\### Reconnaissance, Resource Development \& Initial Access

!\[MITRE Recon](media/Mitre\_001.jpg)



\### Execution \& Persistence  

!\[MITRE Execution](media/Mitre\_002.jpg)



\### Privilege Escalation

!\[MITRE PrivEsc](media/Mitre\_004.jpg)



\### Defense Evasion

!\[MITRE Defense Evasion](media/Mitre\_005.jpg)



\### Credential Access \& Discovery

!\[MITRE Credential Access](media/Mitre\_006.jpg)



\### Lateral Movement, Collection \& C2

!\[MITRE Lateral Movement](media/Mitre\_007.jpg)



\### Exfiltration \& Impact

!\[MITRE Impact](media/Mitre\_003.jpg)



</details>



\*Color legend: Highlighted/colored cells indicate techniques actively used during the penetration test\*



\## 🔵 Defense Implementation



\### Suricata IDS/IPS Rules

Implemented 11 custom rules detecting:

\- HTA application downloads

\- PowerShell stager activity  

\- Metasploit payload signatures

\- Suspicious HTTP traffic on non-standard ports



See \[`suricata-custom.rules`](suricata-custom.rules) for full signatures.



\### pfSense Firewall Configuration

\- Malicious IP blocking

\- HTTP alternate port restrictions

\- Meterpreter port blocking (1024-65535 ranges)



\### WordPress Hardening

\- Login attempt rate limiting (Limit Login Attempts Reloaded)

\- Admin page obfuscation (Hide Login Page plugin)

\- Internal page password protection



\## 🛠️ Tools \& Technologies



\*\*Offensive:\*\* Kali Linux, Metasploit Framework, msfvenom, Burp Suite, gobuster, WPScan, CUPP, John the Ripper



\*\*Defensive:\*\* pfSense, Suricata IDS/IPS, WordPress security plugins



\*\*Infrastructure:\*\* Windows 10/Server, VirtualBox, Active Directory



\## 📜 Training \& Certifications



\- \*\*Cybersecurity Professional Training\*\* - Graduated July 2023 (Overall GPA: 98.8/100, Top of Class with Distinction)



\## 👥 Team



\*\*Haddar DeMerchant\*\* and \*\*Georgy Strenov\*\*



\## 📄 License



This project documentation is provided for educational and portfolio purposes. The techniques demonstrated should only be used in authorized environments.



---



