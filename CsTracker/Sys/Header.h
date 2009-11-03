#include <ntddk.h>

typedef unsigned int UINT;
typedef int*	PINT;

//�ڲ���
#define AFD_SENDTO		0x12023 
#define AFD_RECVFROM	0x1201B

//�����붨��
#define StartMonitor	CTL_CODE(FILE_DEVICE_UNKNOWN,0x811,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define StopMonitor		CTL_CODE(FILE_DEVICE_UNKNOWN,0x812,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define SetEvent		CTL_CODE(FILE_DEVICE_UNKNOWN,0x813,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define SetFilter		CTL_CODE(FILE_DEVICE_UNKNOWN,0x814,METHOD_BUFFERED,FILE_ANY_ACCESS)

//�ṹ�嶨��
typedef struct _TA_ADDRESS {
	USHORT  AddressLength;
	USHORT  AddressType;
	UCHAR	Address[1];
} TA_ADDRESS, *PTA_ADDRESS;

typedef struct _TRANSPORT_ADDRESS {
	LONG  TAAddressCount;
	TA_ADDRESS  Address[1];
} TRANSPORT_ADDRESS, *PTRANSPORT_ADDRESS;

typedef struct _AFD_WSABUF {
    UINT  len;
    PCHAR buf;
} AFD_WSABUF, *PAFD_WSABUF;


typedef struct _AFD_RECV_INFO_UDP {
    PAFD_WSABUF			BufferArray;
    ULONG				BufferCount;
    ULONG				AfdFlags;
    ULONG				TdiFlags;
    PVOID				Address;
    PINT				AddressLength;
} AFD_RECV_INFO_UDP, *PAFD_RECV_INFO_UDP;

typedef struct _AFD_SEND_INFO_UDP {
    PAFD_WSABUF			BufferArray;
    ULONG				BufferCount;
    ULONG				AfdFlags;
    ULONG				Padding[9];
    ULONG				SizeOfRemoteAddress;
    PVOID				RemoteAddress;
} AFD_SEND_INFO_UDP, *PAFD_SEND_INFO_UDP;




//SSDT Table
#pragma pack(1)
typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase;
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()
__declspec(dllimport) ServiceDescriptorTableEntry_t KeServiceDescriptorTable;

typedef NTSTATUS (*NTDEVICEIOCONTROLFILE)(__in HANDLE FileHandle,
										  __in_opt HANDLE Event,
										  __in_opt PIO_APC_ROUTINE ApcRoutine,
										  __in_opt PVOID ApcContext,
										  __out PIO_STATUS_BLOCK IoStatusBlock,
										  __in ULONG IoControlCode,
										  __in_bcount_opt(InputBufferLength) PVOID InputBuffer,
										  __in ULONG InputBufferLength,
										  __out_bcount_opt(OutputBufferLength) PVOID OutputBuffer,
										  __in ULONG OutputBufferLength);

//SSDT Hook ���ܵ������궨��
//ZwXXXX mov eax,(NtNums)
//��д��SSDT����׵�ַ
PVOID* NewSystemCall;
#define HOOK_INDEX(Zw2Nt)				*(PULONG)((PUCHAR)Zw2Nt+1)
#define HOOK(ZwIndex,NewFunc,NtFunc)	NtFunc = (PVOID)InterlockedExchange((PLONG)&NewSystemCall[HOOK_INDEX(ZwIndex)],(LONG)NewFunc)
#define UNHOOK(ZwIndex,NtFunc)			InterlockedExchange((PLONG)&NewSystemCall[HOOK_INDEX(ZwIndex)],(LONG)NtFunc)

//���ڴ洢Hook��Ϣ�Ľṹ��
typedef struct Hook{
	ULONG	ZwIndex;	//ԭʼ������ַ ZwXXXX
	ULONG	NewFunc;	//�滻������ַ
	ULONG	NtFunc;		//����ԭʼ������ַ
}Hook,*pHook;

//�����ýṹ��
typedef struct{
	ULONG	Pid;
	ULONG	Ip;
	ULONG	Length;
	USHORT	Behavior;
	USHORT	Port;
	PVOID	pBuffer;
}Filter,*PFilter;




//////////////////////////////////////////////////////////////////////////
//��������
//////////////////////////////////////////////////////////////////////////
//����ж�غ���
VOID OnUnload(PDRIVER_OBJECT DriverObject);
//Io���ƺ���
NTSTATUS DeviceControl(PDEVICE_OBJECT pDeviceObject,PIRP pIrp);
//�򿪻��߹ر��豸
NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject,PIRP irp);
//��ȡ����
NTSTATUS ReadPacket(PDEVICE_OBJECT DeviceObject,PIRP irp);
// Ssdt Hook ZwDeviceIoControlFile
NTSTATUS SsdtHook(pHook pInfo,BOOLEAN bFlag);
// New Hook Function
NTSTATUS
NTAPI
NewDeviceIoControlFile(__in HANDLE FileHandle,
					   __in_opt HANDLE Event,
					   __in_opt PIO_APC_ROUTINE ApcRoutine,
					   __in_opt PVOID ApcContext,
					   __out PIO_STATUS_BLOCK IoStatusBlock,
					   __in ULONG IoControlCode,
					   __in_bcount_opt(InputBufferLength) PVOID InputBuffer,
					   __in ULONG InputBufferLength,
					   __out_bcount_opt(OutputBufferLength) PVOID OutputBuffer,
					   __in ULONG OutputBufferLength);
