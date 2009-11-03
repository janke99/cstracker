#pragma once
#include <WinSock2.h>
#include <Windows.h>
#include "resource.h"
#include <commctrl.h>
//#include <stdlib.h>
//#include <vector>
//using std::vector;

#pragma comment(lib,"comctl32.lib")
#pragma comment(lib,"WS2_32.lib")


//内部码
#define AFD_SENDTO		0x12023 
#define AFD_RECVFROM	0x1201B

//控制码定义
#define StartMonitor	CTL_CODE(FILE_DEVICE_UNKNOWN,0x811,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define StopMonitor		CTL_CODE(FILE_DEVICE_UNKNOWN,0x812,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define SetEvent		CTL_CODE(FILE_DEVICE_UNKNOWN,0x813,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define SetFilter		CTL_CODE(FILE_DEVICE_UNKNOWN,0x814,METHOD_BUFFERED,FILE_ANY_ACCESS)

//结构体定义
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

//过滤用结构体
typedef struct{
	ULONG	Pid;
	ULONG	Ip;
	ULONG	Length;
	USHORT	Behavior;
	USHORT	Port;
	PVOID	pBuffer;
}Filter,*PFilter;