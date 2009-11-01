//////////////////////////////////////////////////////////////////////////
// Project:	Hook ZwDeviceIoControlFile Function
// Author:	0xQo
// Date:	2009-11-01
//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////
// ͷ�ļ�����
//////////////////////////////////////////////////////////////////////////
#include <ntddk.h>

//////////////////////////////////////////////////////////////////////////
//�궨��
//////////////////////////////////////////////////////////////////////////
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

//////////////////////////////////////////////////////////////////////////
//ȫ�ֱ�������
//////////////////////////////////////////////////////////////////////////
//ȫ���豸����ָ��
PDRIVER_OBJECT pGlobalDvrObj;
//�豸���������������ַ���
UNICODE_STRING device_name = RTL_CONSTANT_STRING(L"\\Device\\CsTracker");
UNICODE_STRING symb_link = RTL_CONSTANT_STRING(L"\\DosDevices\\CsTracker");
//Hook ZwDeviceIoControlFile
Hook Zdicf;


//////////////////////////////////////////////////////////////////////////
//��������
//////////////////////////////////////////////////////////////////////////
//����ж�غ���
VOID OnUnload(PDRIVER_OBJECT DriverObject);
//Io���ƺ���
NTSTATUS DeviceControl(PDEVICE_OBJECT pDeviceObject,PIRP pIrp);
//�򿪻��߹ر��豸
NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject,PIRP irp);\
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

//////////////////////////////////////////////////////////////////////////
// ������ڵ㺯��
//////////////////////////////////////////////////////////////////////////
NTSTATUS DriverEntry(__in PDRIVER_OBJECT pDriverObject,
					 __in PUNICODE_STRING pRegistryPath)
{
	NTSTATUS status;
	PDEVICE_OBJECT device;
	pGlobalDvrObj = pDriverObject;

	//�����豸����
	status = IoCreateDevice(pDriverObject,
							NULL,
							&device_name,
							FILE_DEVICE_UNKNOWN,
							FILE_DEVICE_SECURE_OPEN,
							FALSE,
							&device);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	//���ɷ�������
	status = IoCreateSymbolicLink(&symb_link,&device_name);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(device);
		return status;
	}

	//Hook ZwDeviceIoControlFile
	Zdicf.ZwIndex = HOOK_INDEX(ZwDeviceIoControlFile);
	Zdicf.NewFunc = NewDeviceIoControlFile;
	SsdtHook(&Zdicf,TRUE);

	//������ǲ����
	// ����ж�غ��� 
	pDriverObject->DriverUnload = OnUnload;
	//�򿪡��ر��豸����
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE]  = CreateClose;
	// IOCTL�ַ�����
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;

	return status;
}




//////////////////////////////////////////////////////////////////////////
//����ж�غ���
//////////////////////////////////////////////////////////////////////////
VOID OnUnload(PDRIVER_OBJECT DriverObject)
{
	PDEVICE_OBJECT pdoNextDeviceObj = pGlobalDvrObj->DeviceObject;

	//ɾ����������
	IoDeleteSymbolicLink(&symb_link);

	//UnHook SSDT
	SsdtHook(&Zdicf,FALSE);

	// ɾ�����������豸���
	while(pdoNextDeviceObj)
	{
		PDEVICE_OBJECT pdoThisDeviceObj = pdoNextDeviceObj;
		pdoNextDeviceObj = pdoThisDeviceObj->NextDevice;
		IoDeleteDevice(pdoThisDeviceObj);
	}
}


//////////////////////////////////////////////////////////////////////////
//�򿪻��߹ر��豸
//////////////////////////////////////////////////////////////////////////
NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject,PIRP irp)
{
	return STATUS_NOT_SUPPORTED;
}


//////////////////////////////////////////////////////////////////////////
//IOCONTROL �ַ�����
//////////////////////////////////////////////////////////////////////////
NTSTATUS DeviceControl(PDEVICE_OBJECT pDeviceObject,PIRP pIrp)
{
	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(pIrp);

	ULONG Code = IrpSp->Parameters.DeviceIoControl.IoControlCode;
	ULONG InputLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
	ULONG OutputLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
	PVOID pIoBuff = pIrp->AssociatedIrp.SystemBuffer;

	switch(Code)
	{

	default:
		break;
	}

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return pIrp->IoStatus.Status;
}



//////////////////////////////////////////////////////////////////////////
// Ssdt Hook 
//////////////////////////////////////////////////////////////////////////
NTSTATUS SsdtHook(pHook pInfo,BOOLEAN bFlag)
{
	PMDL pMdl;
	
	//ʹSSDT���д,�������д���׵�ַ
	pMdl = MmCreateMdl(NULL,KeServiceDescriptorTable.ServiceTableBase,KeServiceDescriptorTable.NumberOfServices*4);
	if (!pMdl)
	{
		return STATUS_UNSUCCESSFUL;
	}

	MmBuildMdlForNonPagedPool(pMdl);

	pMdl->MdlFlags = pMdl->MdlFlags|MDL_MAPPED_TO_SYSTEM_VA;
	NewSystemCall = (PVOID*)MmMapLockedPages(pMdl,KernelMode);
	if (!NewSystemCall)
	{
		return STATUS_UNSUCCESSFUL;
	}

	if (bFlag == TRUE)
	{
		//HOOK(pInfo->ZwIndex,pInfo->NewFunc,pInfo->NtFunc);
		pInfo->NtFunc = InterlockedExchange((PLONG)&NewSystemCall[pInfo->ZwIndex],(LONG)pInfo->NewFunc);
	}
	else
	{
		//UNHOOK(pInfo->ZwIndex,pInfo->NtFunc);
		InterlockedExchange((PLONG)&NewSystemCall[pInfo->ZwIndex],(LONG)pInfo->NtFunc);
	}

	return STATUS_SUCCESS;
}


//////////////////////////////////////////////////////////////////////////
// New Hook Function
//////////////////////////////////////////////////////////////////////////
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
								__in ULONG OutputBufferLength)
{

	NTSTATUS status;
	NTDEVICEIOCONTROLFILE NtDeviceIoControlFile = Zdicf.NtFunc;

	status = NtDeviceIoControlFile(FileHandle,Event,ApcRoutine,ApcContext,IoStatusBlock,IoControlCode,InputBuffer,InputBufferLength,OutputBuffer,OutputBufferLength);
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
				DbgPrint("[TCP Recv Packets]\n");
			}
			break;
		case AFD_SEND:
			{
				DbgPrint("[TCP Send Packets]\n");
			}
			break;
		case AFD_SENDTO:
			{
				DbgPrint("[UDP Sendto Packets]\n");
			}
			break;
		case AFD_RECVFROM:
			{
				DbgPrint("[UDP RecvFrom Packets]\n");
			}
			break;
		}
	}__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return status;
	}

	return status;
}