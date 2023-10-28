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