# 5-KG25-30-K2
Tool for generating domains using mutation methods (including TLD, suffixes, prefixes) to identify phishing websites. Complies with Russia Supreme Court decision No. 5-KG25-30-K2 of June 24, 2025

--

### ⚠️ Legal Disclaimer

This software and associated materials are intended solely for proof-of-concept (PoC) and security research purposes. Unauthorized use of this code for real-world phishing attacks, fraudulent activities, or any malicious intent is strictly prohibited.

--

### Sponsored by HydrAttack

### <a href="https://hydrattack.com/" target=_blank><img src="https://github.com/IvanGlinkin/media_support/blob/main/znak.png?raw=true" width="25"><a>  What is HydrAttack 
External Attack Surface Management system <a href="https://hydrattack.com/" target=_blank>HydrAttack</a> is an innovative risk management platform, designed to help identify and mitigate web application risks in completely new ways

<a href="https://twitter.com/EASM_HydrAttack" target=_blank><img src="https://cdn-icons-png.flaticon.com/128/5969/5969020.png" width="50"><a>
<a href="https://t.me/EASM_HydrAttack" target=_blank><img src="https://cdn-icons-png.flaticon.com/128/2111/2111646.png" width="45"><a>
<a href="https://www.linkedin.com/company/HydrAttack" target=_blank><img src="https://cdn-icons-png.flaticon.com/128/174/174857.png" width="45"><a>

---

### HowTo

#### Detailed instruction
  
1. Install Docker (if you have already had it, just skip this step)
   * for Ubuntu: official page: https://docs.docker.com/engine/install/ubuntu/
   * for Windows: https://docs.docker.com/desktop/setup/install/windows-install/
   * for MacOS: https://docs.docker.com/desktop/setup/install/mac-install/

2. Download the repository to your PC
   * Using Git: `git clone https://github.com/IvanGlinkin/HydrAttack-PoC-eMail-Spoofer-Module.git`
   * Download ZIP: https://github.com/IvanGlinkin/HydrAttack-PoC-eMail-Spoofer-Module/archive/refs/heads/main.zip
   
3. Go to the folder
   * U/Linux: `cd HydrAttack-PoC-eMail-Spoofer-Module`
   * Windows: `dir HydrAttack-PoC-eMail-Spoofer-Module`
  
4. Create an image (DO NOT FORGET ABOUT THE DOT (.) )
   
   `docker build -t docker-hydrattack-poc-email-spoofer .`

5. Launch the container
   
   `docker run -it --rm -e DOMAIN=abracadabra.ahha -e SENDTO=your@email.com -e USERNAME=spoofed -e ATTACH=/app/attachment.xlsm -v ./:/app docker-hydrattack-poc-email-spoofer`
   
   * USERNAME - sender username, e.g. *spoofed*@abracadabra.ahha
   * DOMAIN - testing domain name, e.g. *abracadabra.ahha*
   * SENDTO - email address, where to send a report, e.g. *your@email.com*
   * ATTACH - file to attach to the email, e.g. *attachment.xlsm*
---

#### Short instruction
  
```
cd ~/Documents
git clone https://github.com/IvanGlinkin/5-KG25-30-K2.git
cd 5-KG25-30-K2 
docker build -t 5-kg25-30-k2 .
chmod -R 777 checking_domains/ # For saving the output
docker run -it --rm -p 80:80 -v .:/app 5-kg25-30-k2
```
