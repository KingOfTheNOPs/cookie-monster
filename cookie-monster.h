#include <windows.h>

#define SystemHandleInformation 0x10
#define HANDLE_TYPE_FILE 37
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

// TODO, Dynamic resolution of NtQuerySystemInformation
#define SYSCALL_STUB_X64(high, low) ".byte 0x4C,0x8B,0xD1,0xB8,0x"#high",0x"#low",0x00,0x00,0x0F,0x05,0xC3"
NTSTATUS __attribute__((naked)) NtQuerySystemInformation(int SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
	asm(SYSCALL_STUB_X64(36, 0));
}

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