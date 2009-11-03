///////////////////////////////////////////////////////////////////////////
// Project:	Hook ZwDeviceIoControlFile Function
// Author:	0xQo
// Date:	2009-11-01
//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////
// ͷ�ļ�����
//////////////////////////////////////////////////////////////////////////
#include "Header.h"


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
//�¼�����
PVOID	pEventObject = NULL;
//���䡢���˽ṹ��
Filter filter;
Filter Packet;

KMUTEX	kMutex;
ULONG	gPid;


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
	device->Flags |= DO_BUFFERED_IO;

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

	//��ʼ��������
	KeInitializeMutex(&kMutex,NULL);

	//������ǲ����
	// ����ж�غ��� 
	pDriverObject->DriverUnload = OnUnload;
	//�򿪡��ر��豸����
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE]  = CreateClose;
	pDriverObject->MajorFunction[IRP_MJ_READ]   = ReadPacket;
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
	HANDLE hEvent;

	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(pIrp);

	ULONG Code = IrpSp->Parameters.DeviceIoControl.IoControlCode;
	ULONG InputLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
	ULONG OutputLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
	PVOID pIoBuff = pIrp->AssociatedIrp.SystemBuffer;

	switch(Code)
	{
	case StartMonitor:
		{
			DbgPrint("Start Monitor\n");
			SsdtHook(&Zdicf,TRUE);
		}
		break;
	case StopMonitor:
		{
			DbgPrint("Stop Monitor\n");
			SsdtHook(&Zdicf,FALSE);
		}
		break;
	case SetEvent:
		{
			DbgPrint("Set Monitor\n");
			hEvent = *(HANDLE*)pIoBuff;
			ObReferenceObjectByHandle(hEvent,GENERIC_ALL,NULL,KernelMode,&pEventObject,NULL);
			ObDereferenceObject(pEventObject);
		}
		break;
	case SetFilter:
		{
			DbgPrint("Set Filter\n");
			filter = *(Filter*)pIoBuff;
		}
		break;
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

	NTSTATUS status = STATUS_UNSUCCESSFUL;
	USHORT Port;
	ULONG  Ip;
	NTDEVICEIOCONTROLFILE NtDeviceIoControlFile = Zdicf.NtFunc;

	if (IoControlCode!=AFD_SENDTO && IoControlCode!=AFD_RECVFROM)		goto _label;

	if (filter.Behavior!=0 && filter.Behavior!=IoControlCode)			goto _label;

	if (PsGetCurrentProcessId() != filter.Pid)		goto _label;

	if (((PAFD_SEND_INFO_UDP)InputBuffer)->BufferArray->len < filter.Length)		goto _label;

	if (IoControlCode == AFD_SENDTO)
	{
		Port = *(((PTRANSPORT_ADDRESS)((PAFD_SEND_INFO_UDP)InputBuffer)->RemoteAddress)->Address->Address);
		Ip = *(((PTRANSPORT_ADDRESS)((PAFD_SEND_INFO_UDP)InputBuffer)->RemoteAddress)->Address->Address+sizeof(USHORT));
	}
	else
	{
		Port = *(((PTRANSPORT_ADDRESS)((PAFD_RECV_INFO_UDP)InputBuffer)->Address)->Address->Address);
		Ip = *(((PTRANSPORT_ADDRESS)((PAFD_RECV_INFO_UDP)InputBuffer)->Address)->Address->Address+sizeof(USHORT));
	}
	if (Port==filter.Port || Ip==filter.Ip)		goto _label;

	__try{
		KeWaitForSingleObject(&kMutex,Executive,KernelMode,FALSE,NULL);
		Packet.Pid = PsGetCurrentProcessId();
		Packet.Behavior = IoControlCode;
		Packet.Length = ((PAFD_SEND_INFO_UDP)InputBuffer)->BufferArray->len;
		Packet.pBuffer = ((PAFD_SEND_INFO_UDP)InputBuffer)->BufferArray->buf;
		Packet.Port = Port;
		Packet.Ip = Ip;
		KeSetEvent(pEventObject,IO_NO_INCREMENT,FALSE);
		KeWaitForSingleObject(pEventObject,Executive,KernelMode,FALSE,NULL);
		KeReleaseMutex(&kMutex,FALSE);
	}__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return status;
	}

_label:
	return NtDeviceIoControlFile(FileHandle,Event,ApcRoutine,ApcContext,IoStatusBlock,IoControlCode,InputBuffer,InputBufferLength,OutputBuffer,OutputBufferLength);
}



//////////////////////////////////////////////////////////////////////////
//��ȡ����
//////////////////////////////////////////////////////////////////////////
NTSTATUS ReadPacket(PDEVICE_OBJECT DeviceObject,PIRP irp)
{
	ULONG dwRead = 0;
	NTSTATUS status = STATUS_SUCCESS;

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);

	dwRead = stack->Parameters.Read.Length;
	if (irp->AssociatedIrp.SystemBuffer != NULL)
	{
		if (dwRead == sizeof(Filter))
		{
			memcpy(irp->AssociatedIrp.SystemBuffer,&Packet,dwRead);
		}
		else if (dwRead==Packet.Length)
		{
			memcpy(irp->AssociatedIrp.SystemBuffer,Packet.pBuffer,dwRead);
		}
	}

	irp->IoStatus.Status = status;
	irp->IoStatus.Information = dwRead;

	IoCompleteRequest(irp,IO_NO_INCREMENT);

	return status;
}