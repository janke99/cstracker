///////////////////////////////////////////////////////////////////////////
// Project:	Hook ZwDeviceIoControlFile Function
// Author:	0xQo
// Date:	2009-11-01
//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////
// 头文件包含
//////////////////////////////////////////////////////////////////////////
#include "Header.h"


//////////////////////////////////////////////////////////////////////////
//全局变量声明
//////////////////////////////////////////////////////////////////////////
//全局设备对象指针
PDRIVER_OBJECT pGlobalDvrObj;
//设备名、符号链接名字符串
UNICODE_STRING device_name = RTL_CONSTANT_STRING(L"\\Device\\CsTracker");
UNICODE_STRING symb_link = RTL_CONSTANT_STRING(L"\\DosDevices\\CsTracker");
//Hook ZwDeviceIoControlFile
Hook Zdicf;
//事件对象
PVOID	pEventObject = NULL;
//传输、过滤结构体
Filter filter;
Filter Packet;

KMUTEX	kMutex;
ULONG	gPid;


//////////////////////////////////////////////////////////////////////////
// 驱动入口点函数
//////////////////////////////////////////////////////////////////////////
NTSTATUS DriverEntry(__in PDRIVER_OBJECT pDriverObject,
					 __in PUNICODE_STRING pRegistryPath)
{
	NTSTATUS status;
	PDEVICE_OBJECT device;
	pGlobalDvrObj = pDriverObject;

	//生成设备对象
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

	//生成符号链接
	status = IoCreateSymbolicLink(&symb_link,&device_name);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(device);
		return status;
	}

	//Hook ZwDeviceIoControlFile
	Zdicf.ZwIndex = HOOK_INDEX(ZwDeviceIoControlFile);
	Zdicf.NewFunc = NewDeviceIoControlFile;

	//初始化互斥量
	KeInitializeMutex(&kMutex,NULL);

	//设置派遣函数
	// 驱动卸载函数 
	pDriverObject->DriverUnload = OnUnload;
	//打开、关闭设备函数
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE]  = CreateClose;
	pDriverObject->MajorFunction[IRP_MJ_READ]   = ReadPacket;
	// IOCTL分发函数
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;

	return status;
}




//////////////////////////////////////////////////////////////////////////
//驱动卸载函数
//////////////////////////////////////////////////////////////////////////
VOID OnUnload(PDRIVER_OBJECT DriverObject)
{
	PDEVICE_OBJECT pdoNextDeviceObj = pGlobalDvrObj->DeviceObject;

	//删除符号链接
	IoDeleteSymbolicLink(&symb_link);

	//UnHook SSDT
	SsdtHook(&Zdicf,FALSE);

	// 删除所有驱动设备句柄
	while(pdoNextDeviceObj)
	{
		PDEVICE_OBJECT pdoThisDeviceObj = pdoNextDeviceObj;
		pdoNextDeviceObj = pdoThisDeviceObj->NextDevice;
		IoDeleteDevice(pdoThisDeviceObj);
	}
}


//////////////////////////////////////////////////////////////////////////
//打开或者关闭设备
//////////////////////////////////////////////////////////////////////////
NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject,PIRP irp)
{
	return STATUS_NOT_SUPPORTED;
}


//////////////////////////////////////////////////////////////////////////
//IOCONTROL 分发函数
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
	
	//使SSDT表可写,并保存可写的首地址
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
//读取数据
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