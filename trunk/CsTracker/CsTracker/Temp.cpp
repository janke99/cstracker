#include "stdafx.h"
#include "windows.h"
#include "winnt.h"

PVOID pNtDeviceIoControl  = NULL ; 
//

#define AFD_RECV 0x12017

#define AFD_BIND 0x12003

#define AFD_CONNECT 0x12007

#define AFD_SET_CONTEXT 0x12047

#define AFD_RECV 0x12017

#define AFD_SEND 0x1201f

#define AFD_SELECT 0x12024

#define AFD_SENDTO 0x12023 

#define  CV  0x1201f


typedef struct AFD_WSABUF{
	UINT  len ;
	PCHAR  buf ;
}AFD_WSABUF , *PAFD_WSABUF;

typedef struct AFD_INFO {
	PAFD_WSABUF  BufferArray ; 
	ULONG  BufferCount ; 
	ULONG  AfdFlags ;
	ULONG  TdiFlags ;
} AFD_INFO,  *PAFD_INFO;
typedef LONG NTSTATUS;

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

const CHAR GetXX[] = "GET ";
const CHAR PostXX[] = "POST ";
const CHAR HttpXX[] = "HTTP";
//////////////////////////////////////////////////////////////////////////
//
// LookupSendPacket
// ���Send��
// Ŀǰʵ���˹���HTTP����GET AND POST��
//
//////////////////////////////////////////////////////////////////////////

BOOL LookupSendPacket(PVOID Buffer , ULONG Len)
{
	if (Len < 5)
	{
		return FALSE ; 
	}

	//��������쳣����

	if (memcmp(Buffer , GetXX , 4) == 0 
		||
		memcmp(Buffer , PostXX , 5) == 0 )
	{
		return TRUE ; 
	}
	return FALSE ; 
}  
//////////////////////////////////////////////////////////////////////////
//
// LookupRecvPacket
//
// ���Recv��
// ���������ʵ��Recv�����ֵ书��
// Ŀǰʵ���˹���HTTP�������ݰ��Ĺ���
//
//
///////////////////////////////////////////////////////////////////////////
BOOL LookupRecvPacket(PVOID Buffer , ULONG Len)
{
	if (Len < 4)
	{
		return FALSE ; 
	}

	if (memcmp(Buffer , HttpXX , 4) == 0 )
	{
		return TRUE ; 
	}

	return FALSE ; 
}
//hook����

//////////////////////////////////////////////////////////////////////////
//
// NtDeviceIoControlFile��HOOK���� 
// ws2_32.dll��send , recv���ջ���õ�mswsock.dll�ڵ����ݷ��ͺ���
// mswsock.dll�����NtDeviceIoControlFile��TDI Client��������Send Recvָ��
// ���������������أ����Թ������е�TCP �շ�����UDP֮����ɣ�����Ҫ����ָ�
//
//////////////////////////////////////////////////////////////////////////

NTSTATUS __stdcall NewNtDeviceIoControlFile(
	HANDLE FileHandle,
	HANDLE Event OPTIONAL,
	PVOID ApcRoutine OPTIONAL,
	PVOID ApcContext OPTIONAL,
	PVOID IoStatusBlock,
	ULONG IoControlCode,
	PVOID InputBuffer OPTIONAL,
	ULONG InputBufferLength,
	PVOID OutputBuffer OPTIONAL,
	ULONG OutputBufferLength
	)
{

	//�ȵ���ԭʼ����

	LONG stat ; 
	__asm
	{
		push  OutputBufferLength
			push  OutputBuffer
			push  InputBufferLength
			push  InputBuffer 
			push  IoControlCode
			push  IoStatusBlock 
			push  ApcContext
			push  ApcRoutine
			push  Event
			push  FileHandle
			call  pNtDeviceIoControl
			mov    stat ,eax
	}

	//���ԭʼ����ʧ���ˣ�����RECV�����ݣ�

	if (!NT_SUCCESS(stat))
	{
		return stat ; 
	}

	//����Ƿ�ΪTCP�շ�ָ��

	if (IoControlCode != AFD_SEND && IoControlCode != AFD_RECV)
	{
		return stat ; 
	}


	//����AFD INFO�ṹ�����SEND��RECV��BUFFER��Ϣ
	//����������������BUFFER���������Ҫ��TRY EXCEPT
	//

	__try
	{
		//��InputBuffer�õ�Buffer��Len

		PAFD_INFO AfdInfo = (PAFD_INFO)InputBuffer ; 
		PVOID Buffer = AfdInfo->BufferArray->buf ; 
		ULONG Len = AfdInfo->BufferArray->len;

		if (IoControlCode == AFD_SEND)
		{
			if (LookupSendPacket(Buffer , Len))
			{
				//���������
				//�������������Ϣ��������DbgView�鿴�������UI��������SendMessage��ʽ~
				OutputDebugString("SendPacket!\n");    
				OutputDebugString((char*)Buffer);
			}
		}
		else
		{
			if (LookupRecvPacket(Buffer , Len))
			{
				OutputDebugString("RecvPacket!\n");
				OutputDebugString((char*)Buffer);
			}
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return stat ; 
	}

	return stat ; 






}


//////////////////////////////////////////////////////////////////////////
//
//  Hook mswsock.dll�������Ntdll!NtDeviceIoControlFile
//  ���������TDI Cilent�����������˷��
//  �ȶ������Σ�RING3����ײ�İ�����~
//
//////////////////////////////////////////////////////////////////////////
void SuperHookDeviceIoControl()
{
	//�õ�ws2_32.dll��ģ���ַ
	HMODULE hMod = LoadLibrary("mswsock.dll");
	if (hMod == 0 )
	{
		return ;
	}

	//�õ�DOSͷ

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hMod ; 

	//���DOSͷ��Ч
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return ; 
	}

	//�õ�NTͷ

	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG)hMod + pDosHeader->e_lfanew);

	//���NTͷ��Ч
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		return ; 
	}

	//������������Ŀ¼�Ƿ����
	if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0 ||
		pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0 )
	{
		return ; 
	}
	//�õ����������ָ��

	PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG)hMod + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	PIMAGE_THUNK_DATA ThunkData ; 

	//���ÿ��������
	while(ImportDescriptor->FirstThunk)
	{
		//�����������Ƿ�Ϊntdll.dll

		char* dllname = (char*)((ULONG)hMod + ImportDescriptor->Name);

		//������ǣ���������һ������

		if (stricmp(dllname , "ntdll.dll") !=0)
		{
			ImportDescriptor ++ ; 
			continue;
		}

		ThunkData = (PIMAGE_THUNK_DATA)((ULONG)hMod + ImportDescriptor->OriginalFirstThunk);

		int no = 1;
		while(ThunkData->u1.Function)
		{
			//��麯���Ƿ�ΪNtDeviceIoControlFile

			char* functionname = (char*)((ULONG)hMod + ThunkData->u1.AddressOfData + 2);
			if (stricmp(functionname , "NtDeviceIoControlFile") == 0 )
			{
				//
				//����ǣ���ô��¼ԭʼ������ַ
				//HOOK���ǵĺ�����ַ
				//
				ULONG myaddr = (ULONG)NewNtDeviceIoControlFile;
				ULONG btw ; 
				PDWORD lpAddr = (DWORD *)((ULONG)hMod + (DWORD)ImportDescriptor->FirstThunk) +(no-1);
				pNtDeviceIoControl = (PVOID)(*(ULONG*)lpAddr) ; 
				WriteProcessMemory(GetCurrentProcess() , lpAddr , &myaddr , sizeof(ULONG), &btw );
				return ; 

			}

			no++;
			ThunkData ++;
		}
		ImportDescriptor ++;
	}
	return ; 
}

//////////////////////////////////////////////////////////////////////////
//
// CheckProcess ����Ƿ�����Ҫ�ҹ��Ľ���
//
//
//////////////////////////////////////////////////////////////////////////

BOOL CheckProcess()
{
	//�ڴ˼�����Ľ��̹���
	return TRUE ;
}

BOOL APIENTRY DllMain( HANDLE hModule, 
					  DWORD  ul_reason_for_call, 
					  LPVOID lpReserved
					  )
{
	//������DLLʱ������API HOOK

	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{  
		//����Ƿ���Ҫ���˵Ľ���
		if (CheckProcess() == FALSE)
		{  
			//������ǣ�����FALSE,������ӽ�����ж��
			return FALSE ; 
		}

		//HOOK API
		SuperHookDeviceIoControl();
	}
	return TRUE;
} 