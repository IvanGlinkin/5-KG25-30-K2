# 5-KG25-30-K2
Tool for generating domain name mutations using various techniques, including Top Level Domain (TLD) changes and suffix modifications. The program is developed for domain name analysis and identification of potential counterfeit or phishing addresses. The app was created in accordance with the requirements of the Supreme Court's Determination on Civil Cases dated June 24, 2025, No. 5-KG25-30-K2. In the determination, the court annulled judicial decisions regarding consumer protection, monetary recovery, and moral damage compensation, as lower courts shifted the burden of proving case circumstances to the plaintiff who lacked the corresponding information and means to identify false representations of services on behalf of the defendant.

---

### ⚠️ Legal Disclaimer

This software and associated materials are intended solely for proof-of-concept (PoC) and security research purposes. Unauthorized use of this code for real-world phishing attacks, fraudulent activities, or any malicious intent is strictly prohibited.

---

### Sponsored by HydrAttack

### <a href="https://hydrattack.com/" target=_blank><img src="https://github.com/IvanGlinkin/media_support/blob/main/znak.png?raw=true" width="25"><a>  What is HydrAttack 
External Attack Surface Management system <a href="https://hydrattack.com/" target=_blank>HydrAttack</a> is an innovative risk management platform, designed to help identify and mitigate web application risks in completely new ways

<a href="https://twitter.com/EASM_HydrAttack" target=_blank><img src="https://cdn-icons-png.flaticon.com/128/5969/5969020.png" width="50"><a>
<a href="https://t.me/HydrAttack" target=_blank><img src="https://cdn-icons-png.flaticon.com/128/2111/2111646.png" width="45"><a>
<a href="https://www.linkedin.com/company/HydrAttack" target=_blank><img src="https://cdn-icons-png.flaticon.com/128/174/174857.png" width="45"><a>

---

### HowTo

#### Detailed instruction
  
1. Install Docker (if you have already had it, just skip this step)
   * for Ubuntu: official page: https://docs.docker.com/engine/install/ubuntu/
   * for Windows: https://docs.docker.com/desktop/setup/install/windows-install/
   * for MacOS: https://docs.docker.com/desktop/setup/install/mac-install/

2. Download the repository to your PC
   * Using Git: `git clone https://github.com/IvanGlinkin/5-KG25-30-K2.git`
   * Download ZIP: https://github.com/IvanGlinkin/5-KG25-30-K2/archive/refs/heads/main.zip
   
3. Go to the folder
   * U/Linux: `cd 5-KG25-30-K2`
   * Windows: `dir 5-KG25-30-K2`
  
4. Create an image (DO NOT FORGET ABOUT THE DOT (.) )
   
   `docker build -t 5-kg25-30-k2 .`

5. Adjust right/atributs

   *U/Linux: `chmod -R 777 checking_domains/`

   Apache inside the docker is working under www-data rights hence does not have privileges to write data (reports) into the host folder!

7. Launch the container
   
   `docker run -it --rm -p 80:80 -v .:/app 5-kg25-30-k2`
   
8. Open the browser and enter

   `http://localhost:80` 
   
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
